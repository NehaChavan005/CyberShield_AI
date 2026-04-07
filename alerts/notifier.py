from alerts.email_alert import send_email_alert
from alerts.sms_alert import send_sms_alert
from alerts.ui_alert import build_ui_notification_payload


def _safe_channel_send(channel_name: str, sender, alert: dict) -> dict:
    try:
        response = sender(alert)
        if isinstance(response, dict):
            return response
        return {"status": "error", "reason": f"{channel_name}_returned_invalid_payload"}
    except Exception as exc:
        return {"status": "error", "reason": str(exc)}


def send_all_notifications(alert: dict) -> dict:
    return {
        "email": _safe_channel_send("email", send_email_alert, alert),
        "sms": _safe_channel_send("sms", send_sms_alert, alert),
        "ui": _safe_channel_send("ui", build_ui_notification_payload, alert),
    }
