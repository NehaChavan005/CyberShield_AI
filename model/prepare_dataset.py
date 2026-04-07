import pandas as pd
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Correct dataset path
DATASET_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_FILE = os.path.join(DATASET_DIR, "final_dataset.csv")

COLUMNS = [
    "timestamp","source_ip","destination_ip","protocol","port",
    "packet_size","request_rate","failed_logins","malware_signature",
    "traffic_type","attack_type","label"
]

def normalize_columns(df):
    df.columns = [c.lower() for c in df.columns]

    column_map = {
        "src_ip": "source_ip",
        "dst_ip": "destination_ip",
        "protocol_type": "protocol",
        "service": "protocol",
        "attack": "attack_type",
        "attack_cat": "attack_type",
        "class": "label",
    }

    df.rename(columns={k: v for k, v in column_map.items() if k in df.columns}, inplace=True)

    # Add missing columns
    for col in COLUMNS:
        if col not in df.columns:
            if col == "label":
                df[col] = 0
            elif col in ["traffic_type","attack_type","malware_signature"]:
                df[col] = "none"
            else:
                df[col] = None

    df = df[COLUMNS]

    # 🔥 IMPORTANT FIX (REMOVE dataset_source COMPLETELY)
    df.drop(columns=["dataset_source"], inplace=True, errors="ignore")

    return df


def load_and_prepare():
    datasets = []

    try:
        synthetic = pd.read_csv(os.path.join(DATASET_DIR, "cyber_attacks_dataset.csv"))
        synthetic = normalize_columns(synthetic)
        datasets.append(synthetic)
        print("Loaded synthetic dataset")
    except Exception as e:
        print("Error loading synthetic dataset:", e)

    if datasets:
        final_dataset = pd.concat(datasets, ignore_index=True)
        final_dataset.to_csv(OUTPUT_FILE, index=False)
        print(f"Final dataset saved to {OUTPUT_FILE}")
    else:
        print("No datasets loaded.")


if __name__ == "__main__":
    load_and_prepare()
