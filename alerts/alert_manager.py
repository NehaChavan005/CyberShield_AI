import json
import logging
import os
from datetime import datetime, timezone
from ipaddress import ip_address

import requests

from alerts.notifier import send_all_notifications
from utils.env_loader import load_project_env


load_project_env()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_STORE_PATH = os.path.join(BASE_DIR, "data", "alerts.json")
ALERT_HISTORY_LIMIT = 1000
COOLDOWN_SECONDS = 60
GEOLOOKUP_TIMEOUT = 4
IP_API_URL = "http://ip-api.com/json/{ip}"
GEOIP2_DB_PATH = os.getenv("CYBERSHIELD_GEOIP2_DB_PATH")
PRIVATE_NETWORK_LABELS = {"private", "loopback", "reserved", "multicast", "link-local"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _default_store() -> dict:
    return {
        "alerts": [],
        "cooldowns": {},
        "geo_cache": {},
        "updated_at": None,
    }


def load_alert_store() -> dict:
    if not os.path.exists(ALERT_STORE_PATH):
        return _default_store()

    try:
        with open(ALERT_STORE_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        logging.exception("Failed to load alert store from %s", ALERT_STORE_PATH)
        return _default_store()

    store = _default_store()
    if isinstance(data, dict):
        store.update(data)
    if not isinstance(store.get("alerts"), list):
        store["alerts"] = []
    if not isinstance(store.get("cooldowns"), dict):
        store["cooldowns"] = {}
    if not isinstance(store.get("geo_cache"), dict):
        store["geo_cache"] = {}
    return store


def save_alert_store(store: dict) -> None:
    payload = _default_store()
    if isinstance(store, dict):
        payload.update(store)
    payload["updated_at"] = _utc_now()
    os.makedirs(os.path.dirname(ALERT_STORE_PATH), exist_ok=True)
    with open(ALERT_STORE_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _severity_from_result(result: dict) -> str:
    risk_level = str((result.get("ai_analysis") or {}).get("risk_level", "")).upper()
    if risk_level in {"CRITICAL", "HIGH"}:
        return "HIGH"
    if risk_level == "MEDIUM":
        return "MEDIUM"
    return "LOW"


def _derive_confidence(probability) -> float | None:
    if not probability or len(probability) < 2:
        return None
    try:
        return round(max(float(probability[0]), float(probability[1])) * 100, 2)
    except (TypeError, ValueError):
        return None


def _is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        candidate = ip_address(str(value).strip())
    except ValueError:
        return False
    return candidate.is_global


def _private_ip_metadata(ip_value: str) -> dict:
    try:
        candidate = ip_address(ip_value)
    except ValueError:
        category = "unresolved"
    else:
        if candidate.is_private:
            category = "private"
        elif candidate.is_loopback:
            category = "loopback"
        elif candidate.is_multicast:
            category = "multicast"
        elif candidate.is_reserved:
            category = "reserved"
        elif candidate.is_link_local:
            category = "link-local"
        else:
            category = "unresolved"
    return {
        "status": "unavailable",
        "query": ip_value,
        "country": None,
        "region": None,
        "city": None,
        "lat": None,
        "lon": None,
        "isp": None,
        "org": None,
        "source": "local",
        "note": f"Geolocation skipped for {category} address.",
    }


def _lookup_geolocation(ip_value: str, geo_cache: dict) -> dict:
    cached = geo_cache.get(ip_value)
    if isinstance(cached, dict):
        return cached

    if not _is_public_ip(ip_value):
        geo = _private_ip_metadata(ip_value)
        geo_cache[ip_value] = geo
        return geo

    geo = _lookup_geoip2(ip_value)
    if geo:
        geo_cache[ip_value] = geo
        return geo

    params = {
        "fields": "status,message,country,regionName,city,lat,lon,isp,org,query",
    }
    try:
        response = requests.get(
            IP_API_URL.format(ip=ip_value),
            params=params,
            timeout=GEOLOOKUP_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("status") == "success":
            geo = {
                "status": "success",
                "query": payload.get("query") or ip_value,
                "country": payload.get("country"),
                "region": payload.get("regionName"),
                "city": payload.get("city"),
                "lat": payload.get("lat"),
                "lon": payload.get("lon"),
                "isp": payload.get("isp"),
                "org": payload.get("org"),
                "source": "ip-api",
                "note": None,
            }
        else:
            geo = {
                "status": "unavailable",
                "query": ip_value,
                "country": None,
                "region": None,
                "city": None,
                "lat": None,
                "lon": None,
                "isp": None,
                "org": None,
                "source": "ip-api",
                "note": payload.get("message") or "IP geolocation lookup failed.",
            }
    except requests.RequestException as exc:
        geo = {
            "status": "unavailable",
            "query": ip_value,
            "country": None,
            "region": None,
            "city": None,
            "lat": None,
            "lon": None,
            "isp": None,
            "org": None,
            "source": "ip-api",
            "note": str(exc),
        }

    geo_cache[ip_value] = geo
    return geo


def _lookup_geoip2(ip_value: str) -> dict | None:
    if not GEOIP2_DB_PATH or not os.path.exists(GEOIP2_DB_PATH):
        return None

    try:
        import geoip2.database
    except Exception:
        return None

    try:
        with geoip2.database.Reader(GEOIP2_DB_PATH) as reader:
            response = reader.city(ip_value)
    except Exception as exc:
        return {
            "status": "unavailable",
            "query": ip_value,
            "country": None,
            "region": None,
            "city": None,
            "lat": None,
            "lon": None,
            "isp": None,
            "org": None,
            "source": "geoip2",
            "note": str(exc),
        }

    subdivision = response.subdivisions.most_specific if response.subdivisions else None
    location = response.location
    return {
        "status": "success",
        "query": ip_value,
        "country": response.country.name,
        "region": subdivision.name if subdivision else None,
        "city": response.city.name,
        "lat": location.latitude,
        "lon": location.longitude,
        "isp": None,
        "org": None,
        "source": "geoip2",
        "note": None,
    }


def create_structured_alert(source_data: dict, result: dict, geo_cache: dict | None = None) -> dict:
    source_data = source_data or {}
    result = result or {}
    ai_analysis = result.get("ai_analysis") or {}
    attacker_ip = str(source_data.get("source_ip") or "unknown")
    timestamp = str(source_data.get("timestamp") or _utc_now())
    geolocation = _lookup_geolocation(attacker_ip, geo_cache or {})
    severity = _severity_from_result(result)
    attack_type = str(ai_analysis.get("attack_type") or source_data.get("attack_type") or "Unknown")
    confidence = _derive_confidence(result.get("probability"))
    return {
        "alert_id": f"alert-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        "timestamp": timestamp,
        "attacker_ip": attacker_ip,
        "target_ip": source_data.get("destination_ip"),
        "attack_type": attack_type,
        "severity": severity,
        "risk_level": str(ai_analysis.get("risk_level") or severity).upper(),
        "protocol": source_data.get("protocol"),
        "port": source_data.get("port"),
        "packet_size": source_data.get("packet_size"),
        "request_rate": source_data.get("request_rate"),
        "failed_logins": source_data.get("failed_logins"),
        "traffic_type": source_data.get("traffic_type"),
        "malware_signature": source_data.get("malware_signature"),
        "prediction": int(result.get("prediction", 0) or 0),
        "confidence": confidence,
        "summary": ai_analysis.get("explanation") or "Attack detected by the CyberShield-AI model.",
        "remediation": ai_analysis.get("remediation"),
        "policy_override": bool(ai_analysis.get("policy_override")),
        "threat_intel_score": (result.get("threat_intelligence") or {}).get("highest_score", 0),
        "blacklist_match": bool((result.get("threat_intelligence") or {}).get("blacklist_match")),
        "model_version": result.get("model_version"),
        "geolocation": geolocation,
        "notification_results": {},
        "cooldown_applied": False,
        "cooldown_seconds_remaining": 0,
        "notification_status": "pending",
    }


def _apply_cooldown(alert: dict, store: dict) -> tuple[bool, int]:
    attacker_ip = str(alert.get("attacker_ip") or "").strip()
    alert_time = _parse_timestamp(alert.get("timestamp")) or datetime.now(timezone.utc)
    if not attacker_ip:
        return True, 0

    last_sent = _parse_timestamp(store.get("cooldowns", {}).get(attacker_ip))
    if not last_sent:
        store["cooldowns"][attacker_ip] = alert_time.isoformat()
        return True, 0

    elapsed = (alert_time.astimezone(timezone.utc) - last_sent.astimezone(timezone.utc)).total_seconds()
    if elapsed >= COOLDOWN_SECONDS:
        store["cooldowns"][attacker_ip] = alert_time.isoformat()
        return True, 0

    remaining = max(0, int(COOLDOWN_SECONDS - elapsed))
    return False, remaining


def _persist_alert(alert: dict, store: dict) -> dict:
    store["alerts"].append(alert)
    store["alerts"] = store["alerts"][-ALERT_HISTORY_LIMIT:]
    save_alert_store(store)
    return alert


def handle_detection_alert(source_data: dict, result: dict) -> dict | None:
    if int(result.get("prediction", 0) or 0) != 1:
        return None

    store = load_alert_store()
    alert = create_structured_alert(source_data, result, geo_cache=store.get("geo_cache", {}))
    should_notify, cooldown_remaining = _apply_cooldown(alert, store)

    if should_notify:
        notification_results = send_all_notifications(alert)
        alert["notification_results"] = notification_results
        failures = [
            channel for channel, details in notification_results.items()
            if isinstance(details, dict) and details.get("status") == "error"
        ]
        skipped = [
            channel for channel, details in notification_results.items()
            if channel != "ui" and isinstance(details, dict) and details.get("status") == "skipped"
        ]
        sent_channels = [
            channel for channel, details in notification_results.items()
            if isinstance(details, dict) and details.get("status") == "sent"
        ]
        if failures:
            alert["notification_status"] = "partial_failure"
        elif sent_channels:
            alert["notification_status"] = "sent"
        elif skipped:
            alert["notification_status"] = "skipped"
        else:
            alert["notification_status"] = "queued"
    else:
        alert["cooldown_applied"] = True
        alert["cooldown_seconds_remaining"] = cooldown_remaining
        alert["notification_status"] = "cooldown_suppressed"
        alert["notification_results"] = {
            "email": {"status": "skipped", "reason": "cooldown_active"},
            "sms": {"status": "skipped", "reason": "cooldown_active"},
            "ui": {"status": "queued"},
        }

    _persist_alert(alert, store)
    return alert


def get_recent_alerts(limit: int = 20, include_suppressed: bool = True) -> list[dict]:
    store = load_alert_store()
    alerts = list(reversed(store.get("alerts", [])))
    if not include_suppressed:
        alerts = [alert for alert in alerts if not alert.get("cooldown_applied")]
    return alerts[: max(1, int(limit))]


def get_alert_dashboard_snapshot(limit: int = 100) -> dict:
    alerts = get_recent_alerts(limit=limit, include_suppressed=True)
    timeline = {}
    attack_types = {}
    severities = {}
    map_points = []

    for alert in reversed(alerts):
        parsed = _parse_timestamp(alert.get("timestamp"))
        if parsed:
            bucket = parsed.astimezone(timezone.utc).replace(second=0, microsecond=0)
            label = bucket.isoformat()
            timeline[label] = timeline.get(label, 0) + 1
        attack_type = str(alert.get("attack_type") or "Unknown")
        severity = str(alert.get("severity") or "LOW").upper()
        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        severities[severity] = severities.get(severity, 0) + 1

        geo = alert.get("geolocation") or {}
        if geo.get("lat") is not None and geo.get("lon") is not None:
            map_points.append(
                {
                    "lat": geo.get("lat"),
                    "lon": geo.get("lon"),
                    "attacker_ip": alert.get("attacker_ip"),
                    "attack_type": attack_type,
                    "severity": severity,
                    "region": ", ".join(
                        part for part in [geo.get("city"), geo.get("region"), geo.get("country")] if part
                    ),
                }
            )

    return {
        "generated_at": _utc_now(),
        "alerts": alerts,
        "timeline": timeline,
        "attack_type_distribution": attack_types,
        "severity_distribution": severities,
        "map_points": map_points,
    }
