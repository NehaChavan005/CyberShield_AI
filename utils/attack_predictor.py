import joblib
import pandas as pd
import os
import logging
import json

from alerts.alert_manager import handle_detection_alert
from utils.ai_remediation import execute_incident_response
from utils.forensics import log_attack_event
from utils.risk_engine import assess_incident_response_need, calculate_risk
from utils.threat_intelligence import auto_blacklist_indicators, enrich_threat_intelligence

logging.basicConfig(level=logging.INFO)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(BASE_DIR, "model", "cybershield_model.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "model", "encoders.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "model", "features.pkl")
METADATA_PATH = os.path.join(BASE_DIR, "model", "feature_metadata.json")
CURRENT_VERSION_PATH = os.path.join(BASE_DIR, "model", "current_model.json")

# Assets (loaded lazily)
model = None
encoders = {}
expected_columns = []
metadata = {}
current_model_manifest = {}
asset_signature = None


def _compute_asset_signature():
    paths = [MODEL_PATH, ENCODER_PATH, FEATURES_PATH, METADATA_PATH, CURRENT_VERSION_PATH]
    signature = []
    for path in paths:
        signature.append(os.path.getmtime(path) if os.path.exists(path) else None)
    return tuple(signature)


def ensure_assets_loaded():
    """Load model, encoders and feature list if not already loaded."""
    global model, encoders, expected_columns, metadata, current_model_manifest, asset_signature
    latest_signature = _compute_asset_signature()
    if model is not None and encoders and expected_columns and asset_signature == latest_signature:
        return
    try:
        asset_signature = latest_signature
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
        if os.path.exists(ENCODER_PATH):
            encoders = joblib.load(ENCODER_PATH)
        if os.path.exists(FEATURES_PATH):
            expected_columns = joblib.load(FEATURES_PATH)
        if os.path.exists(METADATA_PATH):
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                metadata = json.load(f)
                if not expected_columns and metadata.get("feature_columns"):
                    expected_columns = metadata.get("feature_columns")
        if os.path.exists(CURRENT_VERSION_PATH):
            with open(CURRENT_VERSION_PATH, "r", encoding="utf-8") as f:
                current_model_manifest = json.load(f)
    except Exception as e:
        logging.exception("Failed to load model assets: %s", e)


def preprocess_input(data):
    """Return a DataFrame matching expected_columns and applying encoders for categorical cols.

    - Fills missing columns with reasonable defaults
    - Applies encoders using a safe mapping to avoid transform() errors on unseen labels
    """
    ensure_assets_loaded()

    df = pd.DataFrame([data])

    # Add missing columns: categorical (in encoders) -> 'unknown', numeric -> pd.NA
    for col in expected_columns:
        if col not in df.columns:
            df[col] = "unknown" if col in encoders else pd.NA

    # Keep correct order if available
    if expected_columns:
        df = df[expected_columns]

    # Apply encoders safely: encoders saved as {'col': {'classes': [...]}}
    for col, info in encoders.items():
        if col in df.columns:
            try:
                classes = info.get("classes", [])
                mapping = {str(cls): idx for idx, cls in enumerate(classes)}
                df[col] = df[col].astype(str).map(mapping).fillna(-1).astype(int)
            except Exception:
                df[col] = -1

    # Convert non-encoded columns to numeric where possible; coerce errors to NaN then fill
    for col in df.columns:
        if col not in encoders:
            # coerce to numeric where possible; for strings (like timestamp), becomes NaN
            df[col] = pd.to_numeric(df[col], errors="coerce")
            # Replace NaN with -1 so model receives numeric values
            df[col] = df[col].fillna(-1)

    return df


def predict_attack(data, auto_remediate=False):
    """Predict attack and return a structured dict for consistent caller handling.

    Returns:
      {
        "prediction": int|None,
        "probability": list|None,
        "processed": dict|None,
        "ai_analysis": dict,
        "llm_security_report": str,
        "error": None|str
      }
    """
    ensure_assets_loaded()

    result = {"prediction": None, "probability": None, "processed": None,
              "ai_analysis": None, "llm_security_report": None, "incident_response": None,
              "threat_intelligence": None, "blacklist_updates": [], "error": None,
              "model_version": None, "alert": None}

    try:
        if model is None:
            raise RuntimeError("Model not available. Check that model files exist in model/.")

        processed = preprocess_input(data)
        result["processed"] = processed.to_dict(orient="records")[0] if processed is not None else None

        pred = model.predict(processed)[0]
        result["prediction"] = int(pred)

        if hasattr(model, "predict_proba"):
            try:
                result["probability"] = model.predict_proba(processed)[0].tolist()
            except Exception:
                result["probability"] = None
        result["model_version"] = current_model_manifest.get("version_id")

        threat_intelligence = enrich_threat_intelligence(data)
        result["threat_intelligence"] = threat_intelligence

        raw_attack_type = data.get("attack_type", "none")
        model_attack_type = None
        if isinstance(result["processed"], dict):
            model_attack_type = result["processed"].get("attack_type")

        policy_triggered, policy_reason = assess_incident_response_need(
            data,
            result["prediction"],
            result["probability"],
        )
        risk = calculate_risk(raw_attack_type)
        if risk in {"SAFE", "UNKNOWN"}:
            risk = "High" if result["prediction"] == 1 else "Low"

        highest_intel_score = threat_intelligence.get("highest_score", 0)
        blacklist_match = threat_intelligence.get("blacklist_match", False)
        if blacklist_match:
            risk = "CRITICAL"
        elif highest_intel_score >= 80 and str(risk).upper() not in {"CRITICAL"}:
            risk = "HIGH"

        if result["prediction"] == 1:
            explanation = f"Model flagged the sample as malicious. Detected attack type: {raw_attack_type}."
            remediation = "Isolate host, block IP, inspect captured traffic."
        elif blacklist_match:
            explanation = "Traffic hit a known-blacklisted indicator from the local threat intelligence database."
            remediation = "Block the indicator immediately and investigate related systems."
        elif highest_intel_score >= 50:
            explanation = (
                "External threat intelligence reported this indicator as suspicious even though the model "
                "did not classify the sample as malicious."
            )
            remediation = "Contain the source and validate with logs, EDR, and firewall telemetry."
        elif policy_triggered:
            explanation = (
                f"Model confidence was borderline, but policy marked the traffic as dangerous. "
                f"Attack type: {raw_attack_type}. Reason: {policy_reason}"
            )
            remediation = "Contain the source, review firewall actions, and inspect the host immediately."
        else:
            explanation = "Model considers sample normal."
            remediation = "No immediate action required."

        result["ai_analysis"] = {
            "risk_level": risk,
            "explanation": explanation,
            "remediation": remediation,
            "policy_override": policy_triggered,
            "policy_reason": policy_reason,
            "attack_type": raw_attack_type,
            "threat_intel_score": highest_intel_score,
            "blacklist_match": blacklist_match,
        }

        result["blacklist_updates"] = auto_blacklist_indicators(
            data,
            threat_intelligence,
            result["prediction"],
        )
        # Compose a simple detailed report including processed features
        report_lines = [
            f"Prediction: {result['prediction']}",
            f"Model Version: {result['model_version'] or 'unknown'}",
            f"Risk: {risk}",
            f"Attack Type: {raw_attack_type}",
            f"Encoded Attack Type: {model_attack_type}",
        ]
        report_lines.append("Explanation: " + explanation)
        report_lines.append("Remediation: " + remediation)
        report_lines.append("Policy Override: " + ("yes" if policy_triggered else "no"))
        report_lines.append("Policy Reason: " + policy_reason)
        report_lines.append(f"Threat Intel Score: {highest_intel_score}")
        report_lines.append("Blacklist Match: " + ("yes" if blacklist_match else "no"))
        for indicator in threat_intelligence.get("indicators", []):
            report_lines.append(
                "Threat Intel Indicator: "
                f"{indicator.get('type')}={indicator.get('value')} "
                f"(severity={indicator.get('severity')}, score={indicator.get('score')})"
            )
        if result["blacklist_updates"]:
            report_lines.append(
                "Blacklist Updates: "
                + ", ".join(item.get("value", "") for item in result["blacklist_updates"])
            )
        report_lines.append("Processed features:")
        if isinstance(result["processed"], dict):
            for k, v in result["processed"].items():
                report_lines.append(f" - {k}: {v}")
        if auto_remediate and (result["prediction"] == 1 or policy_triggered):
            result["incident_response"] = execute_incident_response(data, result)

        if result["incident_response"]:
            report_lines.append("Incident Response: " + result["incident_response"]["summary"])
            for action in result["incident_response"].get("actions", []):
                action_status = "SUCCESS" if action.get("success") else "FAILED"
                report_lines.append(
                    f" - {action.get('type')}: {action_status} ({action.get('details')})"
                )

        result["llm_security_report"] = "\n".join(report_lines)
        if result["prediction"] == 1:
            result["alert"] = handle_detection_alert(data, result)
        result["forensics_log"] = log_attack_event(result, data)

        return result

    except Exception as e:
        logging.exception("Prediction failed: %s", e)
        result["error"] = str(e)
        return result
