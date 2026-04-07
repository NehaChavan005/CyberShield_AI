def calculate_risk(attack_type):
    risk_map = {
        "DDoS": "CRITICAL",
        "Brute Force": "HIGH",
        "SQL Injection": "HIGH",
        "XSS": "MEDIUM",
        "Port Scan": "LOW",
        "none": "SAFE",
    }
    return risk_map.get(attack_type, "UNKNOWN")


def assess_incident_response_need(traffic_data, prediction, probability=None):
    traffic_data = traffic_data or {}
    normalized_attack_type = str(traffic_data.get("attack_type", "none")).strip()
    normalized_traffic_type = str(traffic_data.get("traffic_type", "normal")).strip().lower()
    request_rate = int(traffic_data.get("request_rate") or 0)
    failed_logins = int(traffic_data.get("failed_logins") or 0)
    suspicious_process = bool(
        traffic_data.get("suspicious_pid") or traffic_data.get("suspicious_process_name")
    )

    if prediction == 1:
        return True, "Model classified the traffic as malicious."

    attack_probability = None
    if isinstance(probability, list) and len(probability) > 1:
        attack_probability = probability[1]

    high_confidence_signals = [
        normalized_attack_type in {"DDoS", "Brute Force", "SQL Injection", "XSS", "Port Scan"},
        normalized_traffic_type == "suspicious",
        request_rate >= 3000,
        failed_logins >= 5,
        suspicious_process,
    ]

    if attack_probability is not None and attack_probability >= 0.45 and sum(high_confidence_signals) >= 2:
        return True, "Policy override triggered because suspicious indicators are high despite model uncertainty."

    if normalized_attack_type == "DDoS" and normalized_traffic_type == "suspicious" and request_rate >= 3000:
        return True, "Policy override triggered for obvious DDoS-like traffic."

    if normalized_attack_type == "Brute Force" and failed_logins >= 5:
        return True, "Policy override triggered for repeated failed logins."

    return False, "No policy override triggered."
