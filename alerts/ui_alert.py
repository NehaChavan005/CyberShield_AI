import html
import json
from collections.abc import Iterable

import streamlit as st


ALERT_AUDIO_BASE64 = (
    "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"
)


def build_ui_notification_payload(alert: dict) -> dict:
    return {
        "status": "queued",
        "title": f"{alert.get('severity', 'LOW')} ALERT",
        "message": (
            f"{alert.get('attack_type', 'Unknown')} from "
            f"{alert.get('attacker_ip', 'n/a')}"
        ),
        "audio": "embedded_alert_wav",
        "banner": "soc_alert_banner",
    }


def initialize_ui_alert_state() -> None:
    st.session_state.setdefault("soc_alert_feed", [])
    st.session_state.setdefault("soc_seen_alert_ids", [])


def sync_ui_alert_state(alerts: Iterable[dict]) -> list[dict]:
    initialize_ui_alert_state()
    alert_list = list(alerts or [])
    st.session_state["soc_alert_feed"] = alert_list

    seen_ids = set(st.session_state.get("soc_seen_alert_ids", []))
    new_alerts = []
    for alert in reversed(alert_list[:10]):
        alert_id = str(alert.get("alert_id") or "")
        if not alert_id or alert_id in seen_ids or alert.get("cooldown_applied"):
            continue
        seen_ids.add(alert_id)
        new_alerts.append(alert)

    st.session_state["soc_seen_alert_ids"] = list(seen_ids)[-300:]
    return new_alerts


def render_audio_html(trigger_key: str, autoplay: bool = True) -> str:
    safe_key = html.escape(str(trigger_key))
    autoplay_attr = " autoplay" if autoplay else ""
    return f"""
    <div id="cybershield-audio-{safe_key}" style="display:none;">
      <audio{autoplay_attr}>
        <source src="data:audio/wav;base64,{ALERT_AUDIO_BASE64}" type="audio/wav">
      </audio>
    </div>
    """


def render_alert_banner_html(alert: dict) -> str:
    attack_type = html.escape(str(alert.get("attack_type") or "Unknown Threat"))
    attacker_ip = html.escape(str(alert.get("attacker_ip") or "n/a"))
    severity = html.escape(str(alert.get("severity") or "LOW"))
    summary = html.escape(str(alert.get("summary") or "Attack detected"))
    return f"""
    <div class="soc-alert-banner severity-{severity.lower()}">
      <div class="soc-alert-banner__pulse"></div>
      <div class="soc-alert-banner__content">
        <span class="soc-alert-banner__eyebrow">Active Incident</span>
        <div class="soc-alert-banner__title">{attack_type}</div>
        <div class="soc-alert-banner__meta">Source IP: {attacker_ip} | Severity: {severity}</div>
        <div class="soc-alert-banner__summary">{summary}</div>
      </div>
    </div>
    """


def export_alerts_to_json(alerts: list[dict]) -> str:
    return json.dumps(alerts, indent=2)
