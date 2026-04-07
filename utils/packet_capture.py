import json
import os
import time
from datetime import datetime, timezone

import pandas as pd

from utils.attack_predictor import predict_attack

try:
    from scapy.all import ARP, Ether, IP, PcapReader, Raw, TCP, UDP, wrpcap

    SCAPY_AVAILABLE = True
except Exception:
    ARP = Ether = IP = PcapReader = Raw = TCP = UDP = wrpcap = None
    SCAPY_AVAILABLE = False


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DATASET_PATH = os.path.join(BASE_DIR, "data", "final_dataset.csv")
DEFAULT_CAPTURE_PATH = os.path.join(BASE_DIR, "data", "dataset_packet_capture.pcap")
DEFAULT_PACKET_COUNT = 10

TCP_PROTOCOLS = {"TCP", "HTTP", "HTTPS"}
UDP_PROTOCOLS = {"UDP", "DNS"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ensure_scapy() -> None:
    if not SCAPY_AVAILABLE:
        raise RuntimeError(
            "Scapy is not available. Install project dependencies with `pip install -r requirements.txt`."
        )


def _coerce_int(value, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _clean_text(value, default: str = "") -> str:
    text = str(value if value is not None else default).strip()
    return text or default


def load_packet_dataset(dataset_path: str = DEFAULT_DATASET_PATH, attack_only: bool = False) -> pd.DataFrame:
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    frame = pd.read_csv(dataset_path)
    if attack_only and "label" in frame.columns:
        frame = frame[frame["label"] == 1]
    if frame.empty:
        raise ValueError("No dataset rows are available for packet replay.")
    return frame.reset_index(drop=True)


def build_packet_from_record(record: dict):
    _ensure_scapy()

    protocol = _clean_text(record.get("protocol"), "TCP").upper()
    source_ip = _clean_text(record.get("source_ip"), "192.168.1.10")
    destination_ip = _clean_text(record.get("destination_ip"), "10.0.0.5")
    port = _coerce_int(record.get("port"), 80)
    packet_size = max(_coerce_int(record.get("packet_size"), 256), 64)

    metadata = {
        "timestamp": _clean_text(record.get("timestamp"), _utc_now()),
        "protocol": protocol,
        "request_rate": _coerce_int(record.get("request_rate"), 0),
        "failed_logins": _coerce_int(record.get("failed_logins"), 0),
        "malware_signature": _clean_text(record.get("malware_signature"), "none"),
        "traffic_type": _clean_text(record.get("traffic_type"), "normal"),
        "attack_type": _clean_text(record.get("attack_type"), "none"),
        "dataset_source": _clean_text(record.get("dataset_source"), "dataset_replay"),
        "label": _coerce_int(record.get("label"), 0),
    }
    payload = Raw(load=json.dumps(metadata, separators=(",", ":")).encode("utf-8"))

    if protocol == "ARP":
        packet = Ether() / ARP(psrc=source_ip, pdst=destination_ip, op=1) / payload
    elif protocol in UDP_PROTOCOLS:
        packet = Ether() / IP(src=source_ip, dst=destination_ip) / UDP(sport=44444, dport=port) / payload
    else:
        packet = Ether() / IP(src=source_ip, dst=destination_ip) / TCP(sport=44444, dport=port) / payload

    current_size = len(packet)
    if current_size < packet_size:
        packet = packet / Raw(load=b"x" * (packet_size - current_size))
    return packet


def _extract_embedded_metadata(packet) -> dict:
    if not packet or not Raw or not packet.haslayer(Raw):
        return {}

    raw_bytes = bytes(packet[Raw].load)
    if not raw_bytes:
        return {}

    metadata_bytes = raw_bytes.split(b"}", 1)[0]
    if not metadata_bytes.endswith(b"}"):
        metadata_bytes += b"}"
    try:
        return json.loads(metadata_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}


def extract_features_from_packet(packet) -> dict:
    _ensure_scapy()

    metadata = _extract_embedded_metadata(packet)

    if packet.haslayer(ARP):
        protocol = "ARP"
        source_ip = getattr(packet[ARP], "psrc", None)
        destination_ip = getattr(packet[ARP], "pdst", None)
        port = 0
    elif packet.haslayer(UDP):
        protocol = "UDP"
        source_ip = getattr(packet[IP], "src", None) if packet.haslayer(IP) else None
        destination_ip = getattr(packet[IP], "dst", None) if packet.haslayer(IP) else None
        port = _coerce_int(getattr(packet[UDP], "dport", 0), 0)
    else:
        protocol = "TCP"
        source_ip = getattr(packet[IP], "src", None) if packet.haslayer(IP) else None
        destination_ip = getattr(packet[IP], "dst", None) if packet.haslayer(IP) else None
        port = _coerce_int(getattr(packet[TCP], "dport", 0), 0) if packet.haslayer(TCP) else 0

    return {
        "timestamp": metadata.get("timestamp") or _utc_now(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": _clean_text(metadata.get("protocol"), protocol) if metadata.get("protocol") else protocol,
        "port": port,
        "packet_size": len(packet),
        "request_rate": _coerce_int(metadata.get("request_rate"), 0),
        "failed_logins": _coerce_int(metadata.get("failed_logins"), 0),
        "malware_signature": _clean_text(metadata.get("malware_signature"), "none"),
        "traffic_type": _clean_text(metadata.get("traffic_type"), "normal"),
        "attack_type": _clean_text(metadata.get("attack_type"), "none"),
        "dataset_source": _clean_text(metadata.get("dataset_source"), "dataset_replay"),
        "label": _coerce_int(metadata.get("label"), 0),
    }


def create_dataset_capture(
    dataset_path: str = DEFAULT_DATASET_PATH,
    output_path: str = DEFAULT_CAPTURE_PATH,
    packet_count: int = DEFAULT_PACKET_COUNT,
    attack_only: bool = False,
) -> dict:
    _ensure_scapy()

    frame = load_packet_dataset(dataset_path=dataset_path, attack_only=attack_only)
    packet_total = max(int(packet_count), 1)
    replace = packet_total > len(frame)
    selected_rows = (
        frame.sample(n=packet_total if replace else min(packet_total, len(frame)), replace=replace)
        .reset_index(drop=True)
        .to_dict(orient="records")
    )
    packets = [build_packet_from_record(row) for row in selected_rows]

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    wrpcap(output_path, packets)

    return {
        "dataset_path": dataset_path,
        "capture_path": output_path,
        "packet_count": len(packets),
        "attack_only": attack_only,
    }


def run_dataset_packet_capture(
    dataset_path: str = DEFAULT_DATASET_PATH,
    capture_path: str = DEFAULT_CAPTURE_PATH,
    packet_count: int = DEFAULT_PACKET_COUNT,
    interval_seconds: float = 0.25,
    attack_only: bool = False,
    auto_remediate: bool = False,
) -> dict:
    _ensure_scapy()

    capture_info = create_dataset_capture(
        dataset_path=dataset_path,
        output_path=capture_path,
        packet_count=packet_count,
        attack_only=attack_only,
    )

    packet_results = []
    with PcapReader(capture_info["capture_path"]) as reader:
        for index, packet in enumerate(reader, start=1):
            features = extract_features_from_packet(packet)
            result = predict_attack(features, auto_remediate=auto_remediate)
            packet_results.append(
                {
                    "packet_number": index,
                    "features": features,
                    "prediction": result.get("prediction"),
                    "risk_level": (result.get("ai_analysis") or {}).get("risk_level"),
                    "attack_type": (result.get("ai_analysis") or {}).get("attack_type"),
                    "confidence": result.get("probability"),
                    "result": result,
                }
            )
            if interval_seconds > 0:
                time.sleep(interval_seconds)

    attack_hits = sum(1 for item in packet_results if item.get("prediction") == 1)
    normal_hits = len(packet_results) - attack_hits

    return {
        "generated_at": _utc_now(),
        "dataset_path": capture_info["dataset_path"],
        "capture_path": capture_info["capture_path"],
        "packet_count": len(packet_results),
        "attack_only": attack_only,
        "interval_seconds": interval_seconds,
        "auto_remediate": auto_remediate,
        "attacks_detected": attack_hits,
        "normal_detected": normal_hits,
        "packets": packet_results,
    }
