import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st

from auth.streamlit_auth import logout_button, require_login
from utils.attack_predictor import predict_attack


user = require_login()

st.title("CyberShield-AI: Cyber Attack Detection Demo")
st.caption(f"Signed in as {user.get('username', 'unknown')}")
logout_button()

st.write(
    "Upload traffic samples or enter values manually to detect if traffic is normal or an attack."
)

protocol = st.selectbox("Protocol", ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "ARP"])
port = st.number_input("Port", min_value=0, max_value=65535, value=80)
packet_size = st.number_input("Packet Size (bytes)", min_value=1, max_value=5000, value=512)
request_rate = st.number_input("Request Rate (req/s)", min_value=0, max_value=10000, value=10)
failed_logins = st.number_input("Failed Logins", min_value=0, max_value=1000, value=0)
source_ip = st.text_input("Source IP", value="45.23.12.11")
auto_remediate = st.checkbox("Enable automated incident response", value=False)

if st.button("Detect Attack"):
    sample = {
        "protocol": protocol,
        "port": port,
        "packet_size": packet_size,
        "request_rate": request_rate,
        "failed_logins": failed_logins,
        "source_ip": source_ip,
    }

    result = predict_attack(sample, auto_remediate=auto_remediate)

    if result.get("error"):
        st.error(f"Prediction error: {result['error']}")
    else:
        if result.get("prediction") == 1:
            st.error("Attack detected")
        else:
            st.success("Normal traffic")
        if result.get("incident_response"):
            st.write(result["incident_response"]["summary"])
