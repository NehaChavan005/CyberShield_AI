import pandas as pd
import random
from datetime import datetime, timedelta
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT = os.path.join(BASE_DIR, "data", "cyber_attacks_dataset.csv")

protocols = ["TCP","UDP","HTTP","HTTPS","DNS","ARP"]
attacks = [
    "none","DDoS","UDP Flood","SYN Flood","Brute Force",
    "SQL Injection","XSS","Port Scan","Ransomware",
    "Trojan","Worm","Spyware","Rootkit",
    "DNS Spoofing","ARP Spoofing","Man in the Middle",
    "Credential Stuffing","Password Spraying",
    "Directory Traversal","Command Injection"
]

traffic_types = ["normal","suspicious"]

def random_ip():
    return ".".join(str(random.randint(1,255)) for _ in range(4))

rows = []
start_time = datetime(2026,3,5,10,0,0)

for i in range(20000):   # generate 20k rows
    attack = random.choice(attacks)

    label = 0 if attack == "none" else 1

    rows.append({
        "timestamp": start_time + timedelta(seconds=i),
        "source_ip": random_ip(),
        "destination_ip": random_ip(),
        "protocol": random.choice(protocols),
        "port": random.choice([21,22,23,25,53,80,443,8080]),
        "packet_size": random.randint(100,1500),
        "request_rate": random.randint(1,5000),
        "failed_logins": random.randint(0,50),
        "malware_signature": "none" if label==0 else f"hash_{attack.lower().replace(' ','_')}",
        "traffic_type": random.choice(traffic_types),
        "attack_type": attack,
        "label": label
    })

df = pd.DataFrame(rows)

df.to_csv(OUTPUT, index=False)

print("Large dataset generated:", df.shape)
print("Saved to:", OUTPUT)