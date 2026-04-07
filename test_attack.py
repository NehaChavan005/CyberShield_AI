from utils.attack_predictor import predict_attack

sample_traffic = {
    "timestamp": "2026-03-05 10:00:03",
    "source_ip": "45.23.12.11",
    "destination_ip": "10.0.0.10",
    "protocol": "TCP",
    "port": 80,
    "packet_size": 1500,
    "request_rate": 5000,
    "failed_logins": 0,
    "malware_signature": "none",
    "traffic_type": "suspicious",
    "attack_type": "DDoS"
}

result = predict_attack(sample_traffic)

if result.get("error"):
    print("Prediction error:", result.get("error"))
else:
    print("Prediction:", result.get("prediction"))
    print("Probability:", result.get("probability"))
    print("AI Analysis:", result.get("ai_analysis"))
    print("Processed:", result.get("processed"))
    print("Incident Response:", result.get("incident_response"))
