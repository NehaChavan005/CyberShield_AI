
import json
import os
import socket
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib import error, parse, request


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLACKLIST_PATH = os.path.join(BASE_DIR, "data", "blacklist_db.json")
VT_API_KEY_ENV = "VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY_ENV = "ABUSEIPDB_API_KEY"
ALT_VT_API_KEY_ENV = "CYBERSHIELD_VIRUSTOTAL_API_KEY"
ALT_ABUSEIPDB_API_KEY_ENV = "CYBERSHIELD_ABUSEIPDB_API_KEY"


def _utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _default_blacklist():
    return {
        "ips": {},
        "domains": {},
        "hashes": {},
        "history": [],
        "updated_at": None,
    }


def load_blacklist_db():
    if not os.path.exists(BLACKLIST_PATH):
        return _default_blacklist()

    try:
        with open(BLACKLIST_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return _default_blacklist()

    default = _default_blacklist()
    default.update(data if isinstance(data, dict) else {})
    for key in ("ips", "domains", "hashes"):
        if not isinstance(default.get(key), dict):
            default[key] = {}
    if not isinstance(default.get("history"), list):
        default["history"] = []
    return default


def save_blacklist_db(data):
    os.makedirs(os.path.dirname(BLACKLIST_PATH), exist_ok=True)
    payload = _default_blacklist()
    payload.update(data if isinstance(data, dict) else {})
    payload["updated_at"] = _utc_now()
    with open(BLACKLIST_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def _normalize_indicator(indicator_type, value):
    cleaned = str(value or "").strip()
    if not cleaned:
        return ""
    return cleaned.lower() if indicator_type == "domain" else cleaned


def get_blacklist_entry(indicator_type, value):
    section_map = {"ip": "ips", "domain": "domains", "hash": "hashes"}
    section = section_map.get(indicator_type)
    if section is None:
        return None

    db = load_blacklist_db()
    normalized = _normalize_indicator(indicator_type, value)
    return db.get(section, {}).get(normalized)


def add_to_blacklist(indicator_type, value, source, reason, metadata=None):
    normalized = _normalize_indicator(indicator_type, value)
    if not normalized:
        return None

    section_map = {"ip": "ips", "domain": "domains", "hash": "hashes"}
    section = section_map.get(indicator_type)
    if section is None:
        raise ValueError(f"Unsupported indicator type: {indicator_type}")

    db = load_blacklist_db()
    entry = {
        "value": normalized,
        "source": source,
        "reason": reason,
        "metadata": metadata or {},
        "listed_at": _utc_now(),
    }
    db[section][normalized] = entry
    db["history"].append({"type": indicator_type, **entry})
    db["history"] = db["history"][-200:]
    save_blacklist_db(db)
    return entry


def _looks_like_hash(value):
    candidate = str(value or "").strip().lower()
    if len(candidate) not in {32, 40, 64}:
        return False
    return all(char in "0123456789abcdef" for char in candidate)


def _looks_like_ip(value):
    try:
        ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _looks_like_domain(value):
    candidate = str(value or "").strip().lower()
    if not candidate or " " in candidate or "/" in candidate:
        return False
    if _looks_like_ip(candidate):
        return False
    return "." in candidate


def _http_json(url, headers=None):
    req = request.Request(url, headers=headers or {})
    with request.urlopen(req, timeout=10) as response:
        body = response.read().decode("utf-8")
        return json.loads(body) if body else {}


def _get_env_value(*names):
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return ""


def query_abuseipdb(ip_value):
    api_key = _get_env_value(ABUSEIPDB_API_KEY_ENV, ALT_ABUSEIPDB_API_KEY_ENV)
    if not api_key:
        return {
            "enabled": False,
            "reason": f"{ABUSEIPDB_API_KEY_ENV} or {ALT_ABUSEIPDB_API_KEY_ENV} not configured.",
        }

    query = parse.urlencode({"ipAddress": ip_value, "maxAgeInDays": 90, "verbose": True})
    url = f"https://api.abuseipdb.com/api/v2/check?{query}"
    headers = {"Key": api_key, "Accept": "application/json"}

    try:
        payload = _http_json(url, headers=headers)
        data = payload.get("data", {})
        return {
            "enabled": True,
            "confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "raw": data,
        }
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        return {"enabled": True, "error": f"HTTP {exc.code}", "details": detail[:500]}
    except (error.URLError, socket.timeout, json.JSONDecodeError) as exc:
        return {"enabled": True, "error": str(exc)}


def query_virustotal(indicator_type, value):
    api_key = _get_env_value(VT_API_KEY_ENV, ALT_VT_API_KEY_ENV)
    if not api_key:
        return {
            "enabled": False,
            "reason": f"{VT_API_KEY_ENV} or {ALT_VT_API_KEY_ENV} not configured.",
        }

    path_map = {
        "ip": f"ip_addresses/{parse.quote(value)}",
        "domain": f"domains/{parse.quote(value)}",
        "hash": f"files/{parse.quote(value)}",
    }
    endpoint = path_map.get(indicator_type)
    if endpoint is None:
        return {"enabled": False, "reason": f"Unsupported VirusTotal indicator type: {indicator_type}"}

    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    headers = {"x-apikey": api_key, "accept": "application/json"}

    try:
        payload = _http_json(url, headers=headers)
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        return {
            "enabled": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "raw": attributes,
        }
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        return {"enabled": True, "error": f"HTTP {exc.code}", "details": detail[:500]}
    except (error.URLError, socket.timeout, json.JSONDecodeError) as exc:
        return {"enabled": True, "error": str(exc)}


def _summarize_indicator(indicator_type, value):
    normalized = _normalize_indicator(indicator_type, value)
    blacklist_entry = get_blacklist_entry(indicator_type, normalized)
    summary = {
        "type": indicator_type,
        "value": normalized,
        "blacklisted": blacklist_entry is not None,
        "blacklist_entry": blacklist_entry,
        "abuseipdb": None,
        "virustotal": None,
        "severity": "low",
        "score": 0,
        "recommendation": "Monitor indicator.",
    }

    if not normalized:
        return None

    if indicator_type == "ip":
        summary["abuseipdb"] = query_abuseipdb(normalized)
    summary["virustotal"] = query_virustotal(indicator_type, normalized)

    score = 0
    if summary["blacklisted"]:
        score += 80

    vt = summary["virustotal"] or {}
    if vt.get("enabled") and not vt.get("error"):
        score += min(int(vt.get("malicious", 0)) * 10, 60)
        score += min(int(vt.get("suspicious", 0)) * 5, 20)

    abuse = summary["abuseipdb"] or {}
    if abuse.get("enabled") and not abuse.get("error"):
        score += int(abuse.get("confidence_score", 0) or 0) // 2

    summary["score"] = min(score, 100)
    if summary["score"] >= 80:
        summary["severity"] = "critical"
        summary["recommendation"] = "Block and investigate immediately."
    elif summary["score"] >= 50:
        summary["severity"] = "high"
        summary["recommendation"] = "Treat as malicious and contain the source."
    elif summary["score"] >= 20:
        summary["severity"] = "medium"
        summary["recommendation"] = "Review closely and monitor for escalation."

    return summary


def _candidate_indicators(payload):
    candidates = []
    for ip_key in ("source_ip", "destination_ip"):
        value = payload.get(ip_key)
        if _looks_like_ip(value):
            candidates.append(("ip", value))

    malware_signature = payload.get("malware_signature")
    if _looks_like_hash(malware_signature):
        candidates.append(("hash", malware_signature))
    elif _looks_like_domain(malware_signature):
        candidates.append(("domain", malware_signature))

    return candidates


def enrich_threat_intelligence(payload):
    indicators = []
    for indicator_type, value in _candidate_indicators(payload or {}):
        summary = _summarize_indicator(indicator_type, value)
        if summary:
            indicators.append(summary)

    highest_score = max((item["score"] for item in indicators), default=0)
    blacklisted = any(item["blacklisted"] for item in indicators)

    intel = {
        "indicators": indicators,
        "highest_score": highest_score,
        "blacklist_match": blacklisted,
        "blacklist_db_path": BLACKLIST_PATH,
        "services": {
            "virustotal_configured": bool(_get_env_value(VT_API_KEY_ENV, ALT_VT_API_KEY_ENV)),
            "abuseipdb_configured": bool(_get_env_value(ABUSEIPDB_API_KEY_ENV, ALT_ABUSEIPDB_API_KEY_ENV)),
        },
    }
    return intel


def auto_blacklist_indicators(payload, threat_intelligence, model_prediction):
    payload = payload or {}
    threat_intelligence = threat_intelligence or {}
    added = []

    for indicator in threat_intelligence.get("indicators", []):
        should_list = indicator.get("blacklisted") or indicator.get("score", 0) >= 80
        if model_prediction == 1 and indicator.get("score", 0) >= 50:
            should_list = True

        if not should_list:
            continue

        indicator_type = indicator.get("type")
        value = indicator.get("value")
        if get_blacklist_entry(indicator_type, value):
            continue

        reason = f"Auto-listed from threat intelligence with score {indicator.get('score', 0)}."
        entry = add_to_blacklist(
            indicator_type,
            value,
            source="threat_intelligence",
            reason=reason,
            metadata={
                "model_prediction": model_prediction,
                "attack_type": payload.get("attack_type"),
                "severity": indicator.get("severity"),
            },
        )
        if entry:
            added.append(entry)

    return added
