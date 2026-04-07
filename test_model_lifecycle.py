from model.model_lifecycle import (
    get_current_model_status,
    list_model_versions,
    retrain_model_from_feedback,
    submit_feedback,
)


sample_feedback = {
    "timestamp": "2026-04-03 12:00:00",
    "source_ip": "185.99.88.77",
    "destination_ip": "10.0.0.25",
    "protocol": "TCP",
    "port": 443,
    "packet_size": 1450,
    "request_rate": 3200,
    "failed_logins": 5,
    "malware_signature": "suspicious.example",
    "traffic_type": "suspicious",
    "attack_type": "DDoS",
}


if __name__ == "__main__":
    print("Current model status before feedback:")
    print(get_current_model_status())

    print("\nSubmitting analyst feedback...")
    feedback = submit_feedback(
        sample=sample_feedback,
        expected_label=1,
        feedback_source="test_script",
        notes="Analyst-confirmed malicious traffic sample.",
    )
    print(feedback)

    print("\nRetraining model using feedback...")
    retrain_result = retrain_model_from_feedback(min_feedback_samples=1, triggered_by="test_script")
    print(retrain_result["message"])
    print("New version:", retrain_result["model_manifest"].get("version_id"))

    print("\nLatest model versions:")
    for version in list_model_versions()[:3]:
        print(version.get("version_id"), version.get("trained_at"))
