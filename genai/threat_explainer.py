import json

def explain_threat(prediction, attack_type, traffic_data):

    if prediction == 0:
        return {
            "risk_level": "Low",
            "explanation": "Traffic appears normal with no malicious patterns detected.",
            "remediation": "No action required."
        }

    attack_knowledge = {

        "DDoS": {
            "risk": "Critical",
            "explanation": "Distributed Denial of Service attack detected. Extremely high request rate indicates attempt to overwhelm server resources.",
            "remediation": "Block source IPs, enable rate limiting, activate DDoS protection."
        },

        "Brute Force": {
            "risk": "High",
            "explanation": "Multiple failed login attempts indicate a brute force attack targeting authentication systems.",
            "remediation": "Temporarily block IP address and enable account lockout policy."
        },

        "SQL Injection": {
            "risk": "Critical",
            "explanation": "Malicious SQL queries detected attempting to manipulate database.",
            "remediation": "Sanitize database inputs and deploy Web Application Firewall (WAF)."
        },

        "XSS": {
            "risk": "Medium",
            "explanation": "Cross-site scripting attempt detected where attacker tries to inject malicious scripts.",
            "remediation": "Implement input validation and output encoding."
        },

        "Port Scan": {
            "risk": "Medium",
            "explanation": "Multiple ports scanned to identify open services.",
            "remediation": "Block scanning IP and monitor network activity."
        },

        "Ransomware": {
            "risk": "Critical",
            "explanation": "Malware signature indicates ransomware infection attempt.",
            "remediation": "Isolate affected system immediately and restore from backup."
        }

    }

    info = attack_knowledge.get(attack_type, {
        "risk": "High",
        "explanation": "Suspicious malicious activity detected.",
        "remediation": "Investigate traffic and block suspicious source."
    })

    return {
        "risk_level": info["risk"],
        "attack_type": attack_type,
        "explanation": info["explanation"],
        "remediation": info["remediation"],
        "traffic_data": traffic_data
    }