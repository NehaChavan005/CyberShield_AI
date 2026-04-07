import csv
import io
import json
import os
from collections import Counter
from datetime import datetime, timezone


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORENSICS_LOG_PATH = os.path.join(BASE_DIR, "data", "attack_history.json")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _default_store() -> dict:
    return {
        "events": [],
        "updated_at": None,
    }


def load_attack_history() -> dict:
    if not os.path.exists(FORENSICS_LOG_PATH):
        return _default_store()

    try:
        with open(FORENSICS_LOG_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return _default_store()

    store = _default_store()
    if isinstance(data, dict):
        store.update(data)
    if not isinstance(store.get("events"), list):
        store["events"] = []
    return store


def save_attack_history(store: dict) -> None:
    os.makedirs(os.path.dirname(FORENSICS_LOG_PATH), exist_ok=True)
    payload = _default_store()
    if isinstance(store, dict):
        payload.update(store)
    payload["updated_at"] = _utc_now()
    with open(FORENSICS_LOG_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def _safe_number(value):
    try:
        if value is None or value == "":
            return None
        number = float(value)
        return int(number) if number.is_integer() else round(number, 2)
    except (TypeError, ValueError):
        return None


def _event_from_result(result: dict, source_data: dict | None = None) -> dict:
    source_data = source_data or {}
    analysis = result.get("ai_analysis") or {}
    threat_intelligence = result.get("threat_intelligence") or {}
    indicators = threat_intelligence.get("indicators", [])
    alert = result.get("alert") or {}
    geolocation = alert.get("geolocation") or {}

    return {
        "event_type": "attack_analysis",
        "event_id": f"evt-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        "alert_id": alert.get("alert_id"),
        "logged_at": _utc_now(),
        "prediction": int(result.get("prediction", 0) or 0),
        "verdict": "attack" if result.get("prediction") == 1 else "normal",
        "risk_level": str(analysis.get("risk_level", "unknown")).upper(),
        "attack_type": analysis.get("attack_type") or source_data.get("attack_type") or "unknown",
        "source_ip": source_data.get("source_ip"),
        "destination_ip": source_data.get("destination_ip"),
        "protocol": source_data.get("protocol"),
        "port": _safe_number(source_data.get("port")),
        "packet_size": _safe_number(source_data.get("packet_size")),
        "request_rate": _safe_number(source_data.get("request_rate")),
        "failed_logins": _safe_number(source_data.get("failed_logins")),
        "traffic_type": source_data.get("traffic_type"),
        "malware_signature": source_data.get("malware_signature"),
        "confidence": _derive_confidence(result.get("probability")),
        "policy_override": bool(analysis.get("policy_override")),
        "policy_reason": analysis.get("policy_reason"),
        "threat_intel_score": threat_intelligence.get("highest_score", 0),
        "blacklist_match": bool(threat_intelligence.get("blacklist_match")),
        "indicator_count": len(indicators),
        "indicators": [
            {
                "type": item.get("type"),
                "value": item.get("value"),
                "severity": item.get("severity"),
                "score": item.get("score"),
            }
            for item in indicators
        ],
        "summary": analysis.get("explanation"),
        "remediation": analysis.get("remediation"),
        "incident_response_summary": (result.get("incident_response") or {}).get("summary"),
        "alert_severity": alert.get("severity"),
        "notification_status": alert.get("notification_status"),
        "cooldown_applied": bool(alert.get("cooldown_applied")),
        "geo_country": geolocation.get("country"),
        "geo_region": geolocation.get("region"),
        "geo_city": geolocation.get("city"),
        "geo_lat": geolocation.get("lat"),
        "geo_lon": geolocation.get("lon"),
    }


def _derive_confidence(probability) -> float | None:
    if not probability or len(probability) < 2:
        return None
    try:
        return round(max(float(probability[0]), float(probability[1])) * 100, 2)
    except (TypeError, ValueError):
        return None


def _scan_event_from_result(scan_result: dict) -> dict:
    open_ports = scan_result.get("open_ports", [])
    findings = scan_result.get("misconfigurations", [])
    return {
        "event_type": "vulnerability_scan",
        "event_id": scan_result.get("scan_id") or f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        "logged_at": scan_result.get("scanned_at") or _utc_now(),
        "verdict": "scan",
        "prediction": 0,
        "risk_level": str(scan_result.get("overall_risk", "LOW")).upper(),
        "attack_type": "Vulnerability Scan",
        "source_ip": None,
        "destination_ip": scan_result.get("resolved_ip"),
        "protocol": "TCP",
        "port": None,
        "packet_size": None,
        "request_rate": None,
        "failed_logins": None,
        "traffic_type": "scanner",
        "malware_signature": None,
        "confidence": None,
        "policy_override": False,
        "policy_reason": None,
        "threat_intel_score": 0,
        "blacklist_match": False,
        "indicator_count": len(open_ports),
        "indicators": [
            {
                "type": "service",
                "value": f"{item.get('port')}/{item.get('service')}",
                "severity": "info",
                "score": 0,
            }
            for item in open_ports
        ],
        "summary": scan_result.get("summary"),
        "remediation": (
            "Review exposed services and address the listed misconfigurations."
            if findings else
            "No misconfiguration heuristics were triggered in this scan."
        ),
        "incident_response_summary": None,
        "scan_target": scan_result.get("target"),
        "resolved_target": scan_result.get("resolved_ip"),
        "ports_scanned": scan_result.get("ports_scanned", []),
        "open_ports": open_ports,
        "service_count": len(open_ports),
        "misconfiguration_count": len(findings),
        "misconfigurations": findings,
    }


def log_attack_event(result: dict, source_data: dict | None = None) -> dict:
    event = _event_from_result(result, source_data)
    store = load_attack_history()
    store["events"].append(event)
    store["events"] = store["events"][-1000:]
    save_attack_history(store)
    return event


def log_vulnerability_scan(scan_result: dict) -> dict:
    event = _scan_event_from_result(scan_result)
    store = load_attack_history()
    store["events"].append(event)
    store["events"] = store["events"][-1000:]
    save_attack_history(store)
    return event


def analyze_attack_history(events: list[dict] | None = None) -> dict:
    if events is None:
        events = load_attack_history().get("events", [])

    total_events = len(events)
    attack_analysis_events = [event for event in events if event.get("event_type", "attack_analysis") == "attack_analysis"]
    scan_events = [event for event in events if event.get("event_type") == "vulnerability_scan"]
    attack_events = [event for event in attack_analysis_events if event.get("prediction") == 1]
    critical_events = [event for event in events if str(event.get("risk_level", "")).upper() == "CRITICAL"]
    policy_events = [event for event in events if event.get("policy_override")]
    blacklist_matches = [event for event in events if event.get("blacklist_match")]
    scan_findings = sum(int(event.get("misconfiguration_count") or 0) for event in scan_events)

    risk_distribution = Counter(str(event.get("risk_level", "UNKNOWN")).upper() for event in events)
    attack_types = Counter(
        str(event.get("attack_type", "unknown"))
        for event in attack_events
        if str(event.get("attack_type", "unknown")).lower() not in {"", "none", "unknown"}
    )
    top_source_ips = Counter(
        str(event.get("source_ip"))
        for event in attack_events
        if event.get("source_ip")
    )
    protocols = Counter(
        str(event.get("protocol", "unknown")).upper()
        for event in events
        if event.get("protocol")
    )

    scores = [
        float(event.get("threat_intel_score", 0))
        for event in events
        if isinstance(event.get("threat_intel_score", 0), (int, float))
    ]
    confidences = [
        float(event.get("confidence"))
        for event in events
        if isinstance(event.get("confidence"), (int, float))
    ]

    recent_events = sorted(
        events,
        key=lambda item: item.get("logged_at", ""),
        reverse=True,
    )[:10]

    return {
        "generated_at": _utc_now(),
        "history_path": FORENSICS_LOG_PATH,
        "totals": {
            "events": total_events,
            "attack_analyses": len(attack_analysis_events),
            "vulnerability_scans": len(scan_events),
            "attacks": len(attack_events),
            "normal": total_events - len(attack_events),
            "critical": len(critical_events),
            "policy_overrides": len(policy_events),
            "blacklist_matches": len(blacklist_matches),
            "scan_findings": scan_findings,
        },
        "averages": {
            "threat_intel_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
            "confidence": round(sum(confidences) / len(confidences), 2) if confidences else 0.0,
        },
        "risk_distribution": dict(risk_distribution),
        "top_attack_types": [{"label": label, "count": count} for label, count in attack_types.most_common(5)],
        "top_source_ips": [{"label": label, "count": count} for label, count in top_source_ips.most_common(5)],
        "protocol_distribution": [{"label": label, "count": count} for label, count in protocols.most_common(5)],
        "recent_events": recent_events,
    }


def export_attack_history_csv(events: list[dict] | None = None) -> bytes:
    if events is None:
        events = load_attack_history().get("events", [])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "event_id",
            "logged_at",
            "verdict",
            "prediction",
            "risk_level",
            "attack_type",
            "source_ip",
            "destination_ip",
            "protocol",
            "port",
            "packet_size",
            "request_rate",
            "failed_logins",
            "traffic_type",
            "confidence",
            "threat_intel_score",
            "blacklist_match",
            "policy_override",
            "indicator_count",
            "summary",
            "remediation",
        ]
    )
    for event in events:
        writer.writerow(
            [
                event.get("event_id"),
                event.get("logged_at"),
                event.get("verdict"),
                event.get("prediction"),
                event.get("risk_level"),
                event.get("attack_type"),
                event.get("source_ip"),
                event.get("destination_ip"),
                event.get("protocol"),
                event.get("port"),
                event.get("packet_size"),
                event.get("request_rate"),
                event.get("failed_logins"),
                event.get("traffic_type"),
                event.get("confidence"),
                event.get("threat_intel_score"),
                event.get("blacklist_match"),
                event.get("policy_override"),
                event.get("indicator_count"),
                event.get("summary"),
                event.get("remediation"),
            ]
        )

    return output.getvalue().encode("utf-8")


def export_attack_history_pdf(events: list[dict] | None = None) -> bytes:
    if events is None:
        events = load_attack_history().get("events", [])

    analysis = analyze_attack_history(events)
    lines = [
        "CyberShield-AI Forensics Report",
        f"Generated at: {analysis.get('generated_at')}",
        f"Total events: {analysis['totals']['events']}",
        f"Detected attacks: {analysis['totals']['attacks']}",
        f"Critical events: {analysis['totals']['critical']}",
        f"Blacklist matches: {analysis['totals']['blacklist_matches']}",
        "",
        "Top attack types:",
    ]

    if analysis["top_attack_types"]:
        for item in analysis["top_attack_types"]:
            lines.append(f"- {item['label']}: {item['count']}")
    else:
        lines.append("- No attack entries recorded yet.")

    lines.extend(["", "Recent events:"])
    if events:
        for event in sorted(events, key=lambda item: item.get("logged_at", ""), reverse=True)[:12]:
            lines.append(
                f"- {event.get('logged_at')} | {event.get('risk_level')} | "
                f"{event.get('attack_type')} | {event.get('source_ip') or 'n/a'}"
            )
    else:
        lines.append("- No events logged yet.")

    return _simple_pdf_from_lines(lines)


def _simple_pdf_from_lines(lines: list[str]) -> bytes:
    escaped_lines = [_escape_pdf_text(line[:105]) for line in lines]
    content_lines = ["BT", "/F1 11 Tf", "50 742 Td", "14 TL"]
    for index, line in enumerate(escaped_lines):
        prefix = "" if index == 0 else "T* "
        content_lines.append(f"{prefix}({line}) Tj")
    content_lines.append("ET")
    content_stream = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R /Resources << /Font << /F1 4 0 R >> >> >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Length {len(content_stream)} >>\nstream\n".encode("latin-1") + content_stream + b"\nendstream",
    ]

    buffer = io.BytesIO()
    buffer.write(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(buffer.tell())
        buffer.write(f"{index} 0 obj\n".encode("latin-1"))
        buffer.write(obj)
        buffer.write(b"\nendobj\n")

    xref_offset = buffer.tell()
    buffer.write(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    buffer.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        buffer.write(f"{offset:010d} 00000 n \n".encode("latin-1"))
    buffer.write(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF"
        ).encode("latin-1")
    )
    return buffer.getvalue()


def _escape_pdf_text(value: str) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )
