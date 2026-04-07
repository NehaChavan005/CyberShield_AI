import os

from utils.env_loader import load_project_env


load_project_env()


def _build_sms_body(alert: dict) -> str:
    return (
        f"CyberShield-AI ALERT {alert.get('severity')} | "
        f"{alert.get('attack_type')} | "
        f"IP {alert.get('attacker_ip')} | "
        f"Time {alert.get('timestamp')} | "
        f"Risk {alert.get('risk_level')}"
    )


def send_sms_alert(alert: dict) -> dict:
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    from_number = os.getenv("CYBERSHIELD_TWILIO_FROM_NUMBER")
    to_number = os.getenv("CYBERSHIELD_TWILIO_TO_NUMBER")

    if not account_sid or not auth_token or not from_number or not to_number:
        return {"status": "skipped", "reason": "twilio_env_not_configured"}

    try:
        from twilio.rest import Client
    except Exception as exc:
        return {"status": "error", "reason": f"twilio_import_failed: {exc}"}

    try:
        client = Client(account_sid, auth_token)
        response = client.messages.create(body=_build_sms_body(alert)[:1600], from_=from_number, to=to_number)
        return {"status": "sent", "message_sid": response.sid, "provider": "twilio"}
    except Exception as exc:
        return {"status": "error", "reason": str(exc)}


def get_sms_diagnostics() -> dict:
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    from_number = os.getenv("CYBERSHIELD_TWILIO_FROM_NUMBER")
    to_number = os.getenv("CYBERSHIELD_TWILIO_TO_NUMBER")
    return {
        "configured": bool(account_sid and auth_token and from_number and to_number),
        "account_sid_present": bool(account_sid),
        "auth_token_present": bool(auth_token),
        "from_number_present": bool(from_number),
        "to_number_present": bool(to_number),
    }
