from utils.attack_predictor import predict_attack
from utils.threat_intelligence import (
    add_to_blacklist,
    enrich_threat_intelligence,
    load_blacklist_db,
    save_blacklist_db,
)


sample_traffic = {
    "timestamp": "2026-04-02 10:00:03",
    "source_ip": "45.23.12.11",
    "destination_ip": "8.8.8.8",
    "protocol": "TCP",
    "port": 443,
    "packet_size": 900,
    "request_rate": 4200,
    "failed_logins": 8,
    "malware_signature": "none",
    "traffic_type": "suspicious",
    "attack_type": "Brute Force",
}


if __name__ == "__main__":
    original_db = load_blacklist_db()
    try:
        add_to_blacklist(
            "ip",
            "45.23.12.11",
            source="test_fixture",
            reason="Seeded local blacklist entry for verification.",
            metadata={"scenario": "local_test"},
        )

        intel = enrich_threat_intelligence(sample_traffic)
        print("Threat Intelligence:")
        print(intel)

        result = predict_attack(sample_traffic)
        print("\nPrediction Result:")
        print(result["ai_analysis"])
        print("\nBlacklist Updates:")
        print(result["blacklist_updates"])
        print("\nBlacklist DB Snapshot:")
        print(load_blacklist_db())
    finally:
        save_blacklist_db(original_db)
