# CyberShield-AI

CyberShield-AI is a cybersecurity operations demo platform that combines machine-learning-based traffic classification with threat intelligence enrichment, alerting, vulnerability scanning, forensic logging, and a SOC-style dashboard.

The project includes:

- A Streamlit dashboard for analysts
- A FastAPI backend for programmatic access
- A trained attack-detection model with versioned artifacts
- Threat intelligence checks using a local blacklist plus optional VirusTotal and AbuseIPDB integrations
- Alerting through UI, email, and SMS
- Vulnerability scanning and exposure-based risk prediction
- Dataset-to-PCAP replay for simulated packet capture and analysis
- Model feedback and retraining workflows

## Features

- **Attack detection pipeline**
  Classifies network traffic samples and returns a structured result with prediction, confidence, risk level, remediation guidance, and alert/forensics metadata.

- **Threat intelligence enrichment**
  Checks IPs, domains, and hashes against:
  local blacklist history, VirusTotal, and AbuseIPDB when API keys are configured.

- **Automated incident response**
  Can attempt local containment actions such as blocking IPs, adding Windows Firewall rules, and terminating suspicious processes.

- **SOC dashboard**
  Streamlit UI for:
  overview metrics, model lifecycle, simulated traffic analysis, packet replay, threat intel lookup, vulnerability scanning, and forensic exports.

- **Model lifecycle management**
  Supports analyst feedback capture, retraining, version history, and current model status tracking.

- **Forensics and reporting**
  Persists attack and scan events to JSON logs and exports reports as CSV and PDF.

## Architecture

High-level flow:

1. Traffic or scan data is submitted from the dashboard or API.
2. The prediction/scanning modules process the input.
3. Threat intelligence and risk scoring enrich the result.
4. Alerts, notifications, and forensic logs are generated.
5. Analysts can review results, submit feedback, and retrain the model.

Core modules:

- [`app/dashboard.py`](e:/P/CyberShield-AI/app/dashboard.py): main Streamlit SOC dashboard
- [`app/api.py`](e:/P/CyberShield-AI/app/api.py): FastAPI service layer
- [`utils/attack_predictor.py`](e:/P/CyberShield-AI/utils/attack_predictor.py): model inference pipeline
- [`utils/threat_intelligence.py`](e:/P/CyberShield-AI/utils/threat_intelligence.py): blacklist + external intel enrichment
- [`utils/vulnerability_scanner.py`](e:/P/CyberShield-AI/utils/vulnerability_scanner.py): TCP port scanning and findings
- [`utils/packet_capture.py`](e:/P/CyberShield-AI/utils/packet_capture.py): dataset replay and PCAP generation
- [`alerts/alert_manager.py`](e:/P/CyberShield-AI/alerts/alert_manager.py): alert persistence, cooldowns, notifications, geolocation
- [`utils/forensics.py`](e:/P/CyberShield-AI/utils/forensics.py): event logging, analysis, CSV/PDF export
- [`model/model_lifecycle.py`](e:/P/CyberShield-AI/model/model_lifecycle.py): feedback, retraining, version inventory
- [`model/train_model.py`](e:/P/CyberShield-AI/model/train_model.py): model training and artifact versioning

## Project Structure

```text
CyberShield-AI/
├── app/        # Streamlit UI and FastAPI app
├── alerts/     # Alert creation, notification channels, UI alert helpers
├── auth/       # JWT auth, user store, Streamlit/API auth helpers
├── data/       # Datasets, logs, alert history, blacklist, feedback
├── genai/      # Optional generative-AI helpers
├── model/      # Model training, lifecycle, artifacts, versions
├── monitor/    # Live monitoring helpers
├── utils/      # Detection, intel, scanning, risk, forensics, remediation
└── test_*.py   # Lightweight test/demo scripts
```

## Requirements

- Python 3.10+ recommended
- Windows is the best fit for the current automated remediation flow because it uses `netsh` and `taskkill`
- Internet access is required only for optional external services such as:
  VirusTotal, AbuseIPDB, SMTP, Twilio, and IP geolocation lookups

Main Python dependencies are listed in [`requirements.txt`](e:/P/CyberShield-AI/requirements.txt).

## Installation

Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root. Use placeholder or local development credentials only.

Common settings:

```env
CYBERSHIELD_JWT_SECRET=replace-with-a-long-random-secret
CYBERSHIELD_JWT_EXPIRE_MINUTES=60

CYBERSHIELD_DEMO_USERNAME=admin
CYBERSHIELD_DEMO_PASSWORD=CyberShield123!
CYBERSHIELD_DEMO_FULL_NAME=CyberShield Admin
```

Optional email alert settings:

```env
CYBERSHIELD_SMTP_HOST=smtp.gmail.com
CYBERSHIELD_SMTP_PORT=587
CYBERSHIELD_EMAIL_USERNAME=your-email@example.com
CYBERSHIELD_EMAIL_PASSWORD=your-app-password
CYBERSHIELD_EMAIL_FROM=your-email@example.com
CYBERSHIELD_EMAIL_TO=recipient@example.com
```

Optional SMS alert settings:

```env
TWILIO_ACCOUNT_SID=your-twilio-account-sid
TWILIO_AUTH_TOKEN=your-twilio-auth-token
CYBERSHIELD_TWILIO_FROM_NUMBER=+10000000000
CYBERSHIELD_TWILIO_TO_NUMBER=+10000000001
```

Optional threat intelligence settings:

```env
VIRUSTOTAL_API_KEY=your-virustotal-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

Optional geolocation database:

```env
CYBERSHIELD_GEOIP2_DB_PATH=C:\path\to\GeoLite2-City.mmdb
```

## Running The Project

### 1. Start the Streamlit dashboard

```powershell
streamlit run app/dashboard.py
```

The dashboard includes:

- Overview
- Model Lifecycle
- Simulate Network Traffic
- Dataset Packet Capture
- Threat Intelligence
- Vulnerability Scanner
- Logging & Forensics

### 2. Start the FastAPI server

```powershell
uvicorn app.api:app --reload
```

Open the interactive docs at:

```text
http://127.0.0.1:8000/docs
```

### 3. Authenticate

Use the configured demo credentials, or create a user through the Streamlit sign-up flow.

## Important API Endpoints

- `POST /auth/login`
- `POST /predict`
- `POST /threat-intel/check`
- `GET /blacklist`
- `POST /blacklist`
- `POST /vulnerability/scan`
- `POST /capture/replay`
- `GET /forensics/history`
- `GET /forensics/analysis`
- `GET /forensics/export/csv`
- `GET /forensics/export/pdf`
- `GET /model/status`
- `GET /model/versions`
- `POST /model/feedback`
- `POST /model/retrain`

## Model And Data Notes

- The main model artifacts live under [`model/`](e:/P/CyberShield-AI/model).
- Versioned training outputs are stored in [`model/versions/`](e:/P/CyberShield-AI/model/versions).
- The training dataset is currently loaded from [`data/final_dataset.csv`](e:/P/CyberShield-AI/data/final_dataset.csv).
- Feedback samples are stored in [`data/model_feedback.json`](e:/P/CyberShield-AI/data/model_feedback.json).
- Retraining builds a combined dataset at [`data/retraining_dataset.csv`](e:/P/CyberShield-AI/data/retraining_dataset.csv).

## Tests

This repository currently uses lightweight script-style tests rather than a full `pytest` suite.

Examples:

```powershell
python test_threat_intel.py
python test_vulnerability_scanner.py
python test_model_lifecycle.py
python test_packet_capture.py
```

## Security Notes

- Do not commit real API keys, email passwords, Twilio tokens, or JWT secrets.
- Use `.env` values meant for local development only.
- Automated remediation uses system commands and can modify local firewall state when enabled.
- Vulnerability scanning should only be used on hosts and networks you are authorized to assess.
- Treat model metrics cautiously until validated on a separate, realistic test set.

## Known Caveats

- Automated response behavior is Windows-oriented.
- Some optional integrations require credentials and external network access.
- `genai/llm_report.py` depends on `google.generativeai`, which is not currently listed in [`requirements.txt`](e:/P/CyberShield-AI/requirements.txt).
- The project persists operational state in JSON files under [`data/`](e:/P/CyberShield-AI/data), so repeated demo runs will accumulate alerts, history, and feedback.

## Suggested Next Improvements

- Add a proper `pytest` test suite
- Replace plaintext sample credentials with sanitized placeholders
- Add Docker support
- Add architecture diagrams and sample API payloads
- Expand live network monitoring and production-safe remediation controls
