#!/usr/bin/env python
"""Generate a synthetic dataset in CIC-IDS2017 format for training SmartGuard AI.

This creates a realistic synthetic network traffic dataset with the same column
names and distributions as the real CIC-IDS2017 dataset. Useful when the original
dataset is unavailable for download.

Usage:
    python scripts/generate_synthetic_dataset.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "datasets" / "cicids2017"

# CIC-IDS2017 feature columns (78 network flow features)
CICIDS_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max",
    "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
    "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets",
    "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std",
    "Active Max", "Active Min", "Idle Mean", "Idle Std",
    "Idle Max", "Idle Min",
]


def generate_benign_traffic(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Generate synthetic benign network traffic flows."""
    data = {}
    # Typical web traffic ports
    data["Destination Port"] = rng.choice([80, 443, 8080, 53, 22, 21, 25, 110, 143, 993], n)
    data["Flow Duration"] = rng.exponential(50000, n).clip(0, 1e8)
    data["Total Fwd Packets"] = rng.poisson(5, n).clip(1, 100)
    data["Total Backward Packets"] = rng.poisson(4, n).clip(0, 80)
    data["Total Length of Fwd Packets"] = rng.exponential(500, n).clip(0, 50000)
    data["Total Length of Bwd Packets"] = rng.exponential(2000, n).clip(0, 200000)
    data["Fwd Packet Length Max"] = rng.exponential(300, n).clip(0, 1500)
    data["Fwd Packet Length Min"] = rng.exponential(20, n).clip(0, 1500)
    data["Fwd Packet Length Mean"] = rng.exponential(100, n).clip(0, 1500)
    data["Fwd Packet Length Std"] = rng.exponential(80, n).clip(0, 1000)
    data["Bwd Packet Length Max"] = rng.exponential(500, n).clip(0, 1500)
    data["Bwd Packet Length Min"] = rng.exponential(20, n).clip(0, 1500)
    data["Bwd Packet Length Mean"] = rng.exponential(200, n).clip(0, 1500)
    data["Bwd Packet Length Std"] = rng.exponential(150, n).clip(0, 1000)
    data["Flow Bytes/s"] = rng.exponential(50000, n).clip(0, 1e9)
    data["Flow Packets/s"] = rng.exponential(100, n).clip(0, 1e6)
    data["Flow IAT Mean"] = rng.exponential(100000, n).clip(0, 1e8)
    data["Flow IAT Std"] = rng.exponential(50000, n).clip(0, 1e8)
    data["Flow IAT Max"] = rng.exponential(200000, n).clip(0, 1e8)
    data["Flow IAT Min"] = rng.exponential(1000, n).clip(0, 1e6)

    # IAT features
    for prefix in ["Fwd", "Bwd"]:
        data[f"{prefix} IAT Total"] = rng.exponential(100000, n).clip(0, 1e8)
        data[f"{prefix} IAT Mean"] = rng.exponential(50000, n).clip(0, 1e8)
        data[f"{prefix} IAT Std"] = rng.exponential(30000, n).clip(0, 1e8)
        data[f"{prefix} IAT Max"] = rng.exponential(100000, n).clip(0, 1e8)
        data[f"{prefix} IAT Min"] = rng.exponential(1000, n).clip(0, 1e6)

    # Flags - mostly 0 for benign
    for flag in ["Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags"]:
        data[flag] = rng.choice([0, 1], n, p=[0.95, 0.05])

    data["Fwd Header Length"] = rng.poisson(20, n).clip(0, 200)
    data["Bwd Header Length"] = rng.poisson(20, n).clip(0, 200)
    data["Fwd Packets/s"] = rng.exponential(50, n).clip(0, 1e5)
    data["Bwd Packets/s"] = rng.exponential(40, n).clip(0, 1e5)
    data["Min Packet Length"] = rng.exponential(10, n).clip(0, 1500)
    data["Max Packet Length"] = rng.exponential(500, n).clip(0, 1500)
    data["Packet Length Mean"] = rng.exponential(200, n).clip(0, 1500)
    data["Packet Length Std"] = rng.exponential(150, n).clip(0, 1000)
    data["Packet Length Variance"] = rng.exponential(20000, n).clip(0, 1e6)

    # TCP flags
    data["FIN Flag Count"] = rng.choice([0, 1], n, p=[0.7, 0.3])
    data["SYN Flag Count"] = rng.choice([0, 1], n, p=[0.5, 0.5])
    data["RST Flag Count"] = rng.choice([0, 1], n, p=[0.9, 0.1])
    data["PSH Flag Count"] = rng.choice([0, 1], n, p=[0.6, 0.4])
    data["ACK Flag Count"] = rng.choice([0, 1], n, p=[0.3, 0.7])
    data["URG Flag Count"] = rng.choice([0, 1], n, p=[0.99, 0.01])
    data["CWE Flag Count"] = rng.choice([0, 1], n, p=[0.99, 0.01])
    data["ECE Flag Count"] = rng.choice([0, 1], n, p=[0.95, 0.05])

    data["Down/Up Ratio"] = rng.exponential(1, n).clip(0, 10)
    data["Average Packet Size"] = rng.exponential(200, n).clip(0, 1500)
    data["Avg Fwd Segment Size"] = rng.exponential(100, n).clip(0, 1500)
    data["Avg Bwd Segment Size"] = rng.exponential(200, n).clip(0, 1500)
    data["Fwd Header Length.1"] = data["Fwd Header Length"]

    # Bulk features - mostly 0 for benign
    for col in ["Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
                 "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate"]:
        data[col] = np.zeros(n)

    data["Subflow Fwd Packets"] = data["Total Fwd Packets"]
    data["Subflow Fwd Bytes"] = data["Total Length of Fwd Packets"]
    data["Subflow Bwd Packets"] = data["Total Backward Packets"]
    data["Subflow Bwd Bytes"] = data["Total Length of Bwd Packets"]

    data["Init_Win_bytes_forward"] = rng.choice([8192, 16384, 32768, 65535, -1], n)
    data["Init_Win_bytes_backward"] = rng.choice([8192, 16384, 32768, 65535, -1], n)
    data["act_data_pkt_fwd"] = rng.poisson(3, n).clip(0, 50)
    data["min_seg_size_forward"] = rng.choice([20, 32, 40], n)

    data["Active Mean"] = rng.exponential(5000, n).clip(0, 1e7)
    data["Active Std"] = rng.exponential(2000, n).clip(0, 1e7)
    data["Active Max"] = rng.exponential(10000, n).clip(0, 1e7)
    data["Active Min"] = rng.exponential(1000, n).clip(0, 1e7)
    data["Idle Mean"] = rng.exponential(100000, n).clip(0, 1e8)
    data["Idle Std"] = rng.exponential(50000, n).clip(0, 1e8)
    data["Idle Max"] = rng.exponential(200000, n).clip(0, 1e8)
    data["Idle Min"] = rng.exponential(10000, n).clip(0, 1e8)

    return pd.DataFrame(data)


def generate_attack_traffic(n: int, rng: np.random.Generator, attack_type: str) -> pd.DataFrame:
    """Generate synthetic attack traffic with distinguishable patterns."""
    df = generate_benign_traffic(n, rng)

    if attack_type in ("DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"):
        # DoS attacks: high packet rate, many forward packets, specific ports
        df["Destination Port"] = rng.choice([80, 443, 8080], n)
        df["Total Fwd Packets"] = rng.poisson(50, n).clip(10, 500)
        df["Flow Packets/s"] = rng.exponential(5000, n).clip(100, 1e6)
        df["Fwd Packets/s"] = rng.exponential(3000, n).clip(50, 1e5)
        df["Flow Duration"] = rng.exponential(5000, n).clip(0, 50000)
        df["SYN Flag Count"] = rng.choice([0, 1], n, p=[0.3, 0.7])
        df["Flow IAT Mean"] = rng.exponential(1000, n).clip(0, 10000)
        df["Flow IAT Min"] = rng.exponential(10, n).clip(0, 100)

    elif attack_type in ("PortScan",):
        # Port scan: many different destination ports, small packets
        df["Destination Port"] = rng.integers(1, 65535, n)
        df["Total Fwd Packets"] = rng.poisson(2, n).clip(1, 10)
        df["Total Backward Packets"] = rng.poisson(1, n).clip(0, 5)
        df["Fwd Packet Length Max"] = rng.exponential(40, n).clip(0, 200)
        df["Flow Duration"] = rng.exponential(1000, n).clip(0, 10000)
        df["Flow IAT Min"] = rng.exponential(5, n).clip(0, 50)
        df["RST Flag Count"] = rng.choice([0, 1], n, p=[0.3, 0.7])

    elif attack_type in ("FTP-Patator", "SSH-Patator"):
        # Brute force: many connections to same port, short flows
        df["Destination Port"] = 21 if "FTP" in attack_type else 22
        df["Total Fwd Packets"] = rng.poisson(3, n).clip(1, 20)
        df["Flow Duration"] = rng.exponential(2000, n).clip(0, 20000)
        df["Fwd Packet Length Mean"] = rng.exponential(30, n).clip(0, 200)

    elif attack_type in ("Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - Sql Injection"):
        # Web attacks: target HTTP ports, larger payloads
        df["Destination Port"] = rng.choice([80, 443, 8080], n)
        df["Fwd Packet Length Max"] = rng.exponential(800, n).clip(100, 1500)
        df["Fwd Packet Length Mean"] = rng.exponential(400, n).clip(50, 1500)
        df["Total Fwd Packets"] = rng.poisson(15, n).clip(3, 100)
        df["PSH Flag Count"] = rng.choice([0, 1], n, p=[0.2, 0.8])

    elif attack_type == "Bot":
        # Bot traffic: periodic, medium-rate traffic
        df["Flow IAT Mean"] = rng.normal(30000, 5000, n).clip(0, 1e6)
        df["Flow IAT Std"] = rng.exponential(1000, n).clip(0, 10000)
        df["Fwd Packets/s"] = rng.exponential(200, n).clip(10, 5000)
        df["Init_Win_bytes_forward"] = rng.choice([29200, 64240], n)

    elif attack_type == "Infiltration":
        # Infiltration: looks like benign but with subtle anomalies
        df["Active Mean"] = rng.exponential(50000, n).clip(0, 1e7)
        df["Idle Mean"] = rng.exponential(500000, n).clip(0, 1e8)
        df["Total Fwd Packets"] = rng.poisson(20, n).clip(5, 200)

    elif attack_type == "Heartbleed":
        # Heartbleed: targets HTTPS, specific payload sizes
        df["Destination Port"] = 443
        df["Fwd Packet Length Max"] = rng.normal(16384, 100, n).clip(0, 65535)
        df["Bwd Packet Length Max"] = rng.exponential(10000, n).clip(1000, 65535)

    elif attack_type == "DDoS":
        # DDoS: extremely high packet rates, many sources
        df["Flow Packets/s"] = rng.exponential(10000, n).clip(500, 1e7)
        df["Fwd Packets/s"] = rng.exponential(8000, n).clip(200, 1e6)
        df["Total Fwd Packets"] = rng.poisson(100, n).clip(20, 1000)
        df["Flow Duration"] = rng.exponential(2000, n).clip(0, 20000)
        df["SYN Flag Count"] = rng.choice([0, 1], n, p=[0.2, 0.8])

    return df


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(42)

    # CIC-IDS2017 attack types and approximate proportions
    n_benign = 30000
    attacks = {
        "DoS Hulk": 4000,
        "PortScan": 3000,
        "DDoS": 2500,
        "DoS GoldenEye": 1500,
        "FTP-Patator": 1200,
        "SSH-Patator": 1000,
        "DoS slowloris": 800,
        "DoS Slowhttptest": 600,
        "Bot": 500,
        "Web Attack - Brute Force": 400,
        "Web Attack - XSS": 200,
        "Web Attack - Sql Injection": 100,
        "Infiltration": 100,
        "Heartbleed": 50,
    }

    print(f"\n{'='*60}")
    print(f"  Generating Synthetic CIC-IDS2017 Dataset")
    print(f"{'='*60}")

    # Generate benign traffic
    print(f"\n  Generating {n_benign:,} BENIGN flows...")
    df_benign = generate_benign_traffic(n_benign, rng)
    df_benign["Label"] = "BENIGN"

    # Generate attack traffic
    attack_dfs = []
    for attack_type, count in attacks.items():
        print(f"  Generating {count:,} {attack_type} flows...")
        df_attack = generate_attack_traffic(count, rng, attack_type)
        df_attack["Label"] = attack_type
        attack_dfs.append(df_attack)

    # Combine and shuffle
    df_all = pd.concat([df_benign] + attack_dfs, ignore_index=True)
    df_all = df_all.sample(frac=1, random_state=42).reset_index(drop=True)

    total_attacks = sum(attacks.values())
    print(f"\n  Total: {len(df_all):,} rows ({n_benign:,} benign + {total_attacks:,} attack)")

    # Save
    output_path = OUTPUT_DIR / "synthetic_cicids2017.csv"
    df_all.to_csv(output_path, index=False)
    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"  Saved to: {output_path} ({size_mb:.1f} MB)")

    # Also create a smaller file for quick testing
    df_small = df_all.sample(n=min(10000, len(df_all)), random_state=42)
    small_path = OUTPUT_DIR / "synthetic_cicids2017_small.csv"
    df_small.to_csv(small_path, index=False)
    small_mb = small_path.stat().st_size / (1024 * 1024)
    print(f"  Small sample saved to: {small_path} ({small_mb:.1f} MB)")

    print(f"\n  Label distribution:")
    for label, count in df_all["Label"].value_counts().items():
        print(f"    {label:<35s} {count:>6,}")

    print(f"\n  ✅ Dataset ready! Train with:")
    print(f"     python scripts/train_on_dataset.py --csv {output_path} --label-col Label")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
