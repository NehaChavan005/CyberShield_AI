import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st

from auth.streamlit_auth import logout_button, require_login
from utils.attack_predictor import predict_attack


st.markdown(
    """
<style>
  .glass {
    background: rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 16px;
    box-shadow: 0 4px 30px rgba(0,0,0,0.1);
    backdrop-filter: blur(5px);
    -webkit-backdrop-filter: blur(5px);
    border: 1px solid rgba(255,255,255,0.1);
  }
</style>
""",
    unsafe_allow_html=True,
)

user = require_login()

st.title("CyberShield AI Threat Monitoring")
st.caption(f"Signed in as {user.get('username', 'unknown')}")
logout_button()

st.header("Simulate Network Traffic")

protocol = st.selectbox("Protocol", ["TCP", "UDP", "HTTP", "HTTPS", "DNS"])
port = st.number_input("Port", value=80)
packet_size = st.slider("Packet Size", 100, 1500, 500)
request_rate = st.slider("Request Rate", 1, 5000, 100)
failed_logins = st.slider("Failed Logins", 0, 50, 0)
source_ip = st.text_input("Source IP", value="45.23.12.11")
suspicious_pid = st.text_input("Suspicious PID", value="")
suspicious_process_name = st.text_input("Suspicious Process Name", value="")
auto_remediate = st.checkbox("Enable automated incident response", value=False)

traffic_type = st.selectbox("Traffic Type", ["normal", "suspicious"])
attack_type = st.selectbox(
    "Attack Type",
    ["none", "DDoS", "Brute Force", "SQL Injection", "XSS", "Port Scan"],
)

if st.button("Analyze Traffic"):
    sample = {
        "protocol": protocol,
        "port": port,
        "packet_size": packet_size,
        "request_rate": request_rate,
        "failed_logins": failed_logins,
        "malware_signature": "none",
        "traffic_type": traffic_type,
        "attack_type": attack_type,
        "source_ip": source_ip,
        "suspicious_pid": int(suspicious_pid) if suspicious_pid.strip().isdigit() else None,
        "suspicious_process_name": suspicious_process_name.strip() or None,
    }

    result = predict_attack(sample, auto_remediate=auto_remediate)

    if result.get("error"):
        st.error(f"Prediction failed: {result['error']}")
    else:
        if result.get("prediction") == 1:
            st.error("Cyber attack detected")
        elif result.get("ai_analysis", {}).get("policy_override"):
            st.warning("High-risk traffic detected by policy override")
        else:
            st.success("Normal traffic")

        with st.container():
            st.markdown('<div class="glass">', unsafe_allow_html=True)
            st.subheader("Risk Level")
            st.write(result.get("ai_analysis", {}).get("risk_level"))

            st.subheader("Detected Attack Type")
            st.write(result.get("ai_analysis", {}).get("attack_type", "unknown"))

            st.subheader("AI Explanation")
            st.write(result.get("ai_analysis", {}).get("explanation"))

            st.subheader("Recommended Remediation")
            st.write(result.get("ai_analysis", {}).get("remediation"))

            if result.get("incident_response"):
                st.subheader("Automated Response")
                st.write(result["incident_response"]["summary"])
                for action in result["incident_response"].get("actions", []):
                    st.write(
                        f"{action.get('type')}: {'SUCCESS' if action.get('success') else 'FAILED'}"
                    )
                    st.caption(action.get("details"))

            st.subheader("Detailed Security Report")
            st.code(result.get("llm_security_report", ""))
            st.markdown("</div>", unsafe_allow_html=True)
