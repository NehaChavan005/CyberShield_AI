import pandas as pd

import utils.attack_predictor as attack_predictor
from utils.packet_capture import (
    DEFAULT_DATASET_PATH,
    SCAPY_AVAILABLE,
    build_packet_from_record,
    extract_features_from_packet,
    run_dataset_packet_capture,
)


if not SCAPY_AVAILABLE:
    print("Packet capture test skipped: scapy is not installed.")
    raise SystemExit(0)


dataset_row = pd.read_csv(DEFAULT_DATASET_PATH).head(1).to_dict(orient="records")[0]
packet = build_packet_from_record(dataset_row)
features = extract_features_from_packet(packet)

assert features["source_ip"] == dataset_row["source_ip"]
assert features["destination_ip"] == dataset_row["destination_ip"]
assert str(features["protocol"]).upper() == str(dataset_row["protocol"]).upper()
assert int(features["request_rate"]) == int(dataset_row["request_rate"])

original_logger = attack_predictor.log_attack_event
attack_predictor.log_attack_event = lambda result, source_data=None: {"skipped": True}

try:
    replay = run_dataset_packet_capture(packet_count=2, interval_seconds=0.0)
    assert replay["packet_count"] == 2
    assert len(replay["packets"]) == 2
    assert replay["capture_path"].endswith(".pcap")
finally:
    attack_predictor.log_attack_event = original_logger

print("Packet capture replay test passed.")
