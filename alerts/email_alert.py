import os
import smtplib
from email.message import EmailMessage

from utils.env_loader import load_project_env


load_project_env()


def _required_email_settings() -> dict:
    return {
        "host": os.getenv("CYBERSHIELD_SMTP_HOST", "smtp.gmail.com"),
        "port": int(os.getenv("CYBERSHIELD_SMTP_PORT", "587")),
        "username": os.getenv("CYBERSHIELD_EMAIL_USERNAME"),
        "password": os.getenv("CYBERSHIELD_EMAIL_PASSWORD"),
        "from_email": os.getenv("CYBERSHIELD_EMAIL_FROM") or os.getenv("CYBERSHIELD_EMAIL_USERNAME"),
        "to_email": os.getenv("CYBERSHIELD_EMAIL_TO"),
    }


def _build_email_body(alert: dict) -> str:
    geo = alert.get("geolocation") or {}
    geo_parts = [geo.get("city"), geo.get("region"), geo.get("country")]
    geo_label = ", ".join(part for part in geo_parts if part) or "Unavailable"
    return "\n".join(
        [
            "CyberShield-AI detected a malicious event.",
            "",
            f"Timestamp: {alert.get('timestamp')}",
            f"Attacker IP: {alert.get('attacker_ip')}",
            f"Target IP: {alert.get('target_ip')}",
            f"Attack Type: {alert.get('attack_type')}",
            f"Severity: {alert.get('severity')}",
            f"Risk Level: {alert.get('risk_level')}",
            f"Protocol: {alert.get('protocol')}",
            f"Port: {alert.get('port')}",
            f"Confidence: {alert.get('confidence')}",
            f"Threat Intel Score: {alert.get('threat_intel_score')}",
            f"Geo: {geo_label}",
            "",
            f"Summary: {alert.get('summary')}",
            f"Remediation: {alert.get('remediation')}",
        ]
    )


def send_email_alert(alert: dict) -> dict:
    settings = _required_email_settings()
    if not settings["username"] or not settings["password"] or not settings["to_email"]:
        missing = [
            name
            for name, value in {
                "CYBERSHIELD_EMAIL_USERNAME": settings["username"],
                "CYBERSHIELD_EMAIL_PASSWORD": settings["password"],
                "CYBERSHIELD_EMAIL_TO": settings["to_email"],
            }.items()
            if not value
        ]
        return {"status": "skipped", "reason": "email_env_not_configured", "missing": missing}

    message = EmailMessage()
    message["Subject"] = (
        f"[CyberShield-AI][{alert.get('severity', 'LOW')}] "
        f"{alert.get('attack_type', 'Unknown')} from {alert.get('attacker_ip', 'n/a')}"
    )
    message["From"] = settings["from_email"]
    message["To"] = settings["to_email"]
    message.set_content(_build_email_body(alert))

    try:
        with smtplib.SMTP(settings["host"], settings["port"], timeout=10) as server:
            server.starttls()
            server.login(settings["username"], settings["password"])
            server.send_message(message)
        return {"status": "sent", "provider": "smtp"}
    except Exception as exc:
        return {"status": "error", "reason": str(exc)}


def get_email_diagnostics() -> dict:
    settings = _required_email_settings()
    return {
        "configured": bool(settings["username"] and settings["password"] and settings["to_email"]),
        "host": settings["host"],
        "port": settings["port"],
        "username_present": bool(settings["username"]),
        "password_present": bool(settings["password"]),
        "from_email_present": bool(settings["from_email"]),
        "to_email_present": bool(settings["to_email"]),
    }
