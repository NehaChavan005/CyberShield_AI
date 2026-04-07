import os
import sys


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from utils.packet_capture import run_dataset_packet_capture


def start_monitor(
    count: int = 10,
    interval_seconds: float = 0.25,
    attack_only: bool = False,
    auto_remediate: bool = False,
):
    print("Starting dataset-backed packet capture replay...")
    result = run_dataset_packet_capture(
        packet_count=count,
        interval_seconds=interval_seconds,
        attack_only=attack_only,
        auto_remediate=auto_remediate,
    )

    print(f"Capture file: {result['capture_path']}")
    print(f"Packets processed: {result['packet_count']}")
    print(f"Attacks detected: {result['attacks_detected']}")
    print(f"Normal detected: {result['normal_detected']}")

    for packet in result["packets"]:
        features = packet["features"]
        verdict = "ATTACK" if packet.get("prediction") == 1 else "NORMAL"
        print(
            f"[{packet['packet_number']}] {verdict} "
            f"{features.get('source_ip')} -> {features.get('destination_ip')} "
            f"{features.get('protocol')}/{features.get('port')} "
            f"risk={packet.get('risk_level')}"
        )

    return result


if __name__ == "__main__":
    start_monitor()
