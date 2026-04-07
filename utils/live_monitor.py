from utils.packet_capture import extract_features_from_packet, run_dataset_packet_capture


def extract_features(packet):
    return extract_features_from_packet(packet)


def start_monitoring(
    packet_count: int = 10,
    interval_seconds: float = 0.25,
    attack_only: bool = False,
    auto_remediate: bool = False,
):
    return run_dataset_packet_capture(
        packet_count=packet_count,
        interval_seconds=interval_seconds,
        attack_only=attack_only,
        auto_remediate=auto_remediate,
    )


if __name__ == "__main__":
    start_monitoring()
