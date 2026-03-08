"""
Capstone Dataset Generator — CICIDS 2017 Style
Generates a realistic synthetic network intrusion detection dataset
modeled after the Canadian Institute for Cybersecurity IDS 2017 dataset.

Features:
- 30 network flow features matching CICIDS 2017 schema
- 6 traffic classes: BENIGN, DDoS, BruteForce, Botnet, WebAttack, PortScan
- Intentional missing values (~4%)
- Intentional noise/inconsistencies (~3%)
- ~10,000 records with realistic class imbalance
"""

import numpy as np
import pandas as pd
from pathlib import Path

rng = np.random.default_rng(42)

# ---------------------------------------------------------------------------
# Class distribution (mimics real-world imbalance)
# ---------------------------------------------------------------------------
CLASSES = {
    "BENIGN":    6000,
    "DDoS":      1500,
    "PortScan":  1000,
    "BruteForce":  700,
    "Botnet":      500,
    "WebAttack":   300,
}
TOTAL = sum(CLASSES.values())

# ---------------------------------------------------------------------------
# Helper: clipped normal draw
# ---------------------------------------------------------------------------
def cnorm(mean, std, low, high, n):
    return np.clip(rng.normal(mean, std, n), low, high)

# ---------------------------------------------------------------------------
# Per-class feature distributions
# ---------------------------------------------------------------------------
def make_class(label, n):
    rows = {}

    if label == "BENIGN":
        rows["Flow Duration"]            = cnorm(50_000, 80_000, 0, 1_000_000, n)
        rows["Total Fwd Packets"]        = cnorm(15, 10, 1, 500, n).astype(int)
        rows["Total Bwd Packets"]        = cnorm(12, 8,  0, 400, n).astype(int)
        rows["Total Length Fwd Pkts"]    = cnorm(2000, 3000, 0, 100_000, n)
        rows["Total Length Bwd Pkts"]    = cnorm(1500, 2500, 0, 80_000,  n)
        rows["Fwd Pkt Len Mean"]         = cnorm(130, 60, 0, 1500, n)
        rows["Bwd Pkt Len Mean"]         = cnorm(120, 55, 0, 1500, n)
        rows["Flow Bytes/s"]             = cnorm(50_000, 40_000, 0, 500_000, n)
        rows["Flow Pkts/s"]              = cnorm(400, 300, 0, 5_000, n)
        rows["Flow IAT Mean"]            = cnorm(5000, 8000, 0, 100_000, n)
        rows["Flow IAT Std"]             = cnorm(8000, 12_000, 0, 200_000, n)
        rows["Fwd IAT Mean"]             = cnorm(6000, 9000, 0, 150_000, n)
        rows["Bwd IAT Mean"]             = cnorm(6000, 9000, 0, 150_000, n)
        rows["Fwd PSH Flags"]            = rng.integers(0, 2, n)
        rows["Bwd PSH Flags"]            = rng.integers(0, 2, n)
        rows["Fwd URG Flags"]            = rng.integers(0, 2, n)
        rows["Bwd URG Flags"]            = rng.integers(0, 2, n)
        rows["Fwd Header Length"]        = cnorm(60, 20, 20, 200, n).astype(int)
        rows["Bwd Header Length"]        = cnorm(60, 20, 20, 200, n).astype(int)
        rows["Fwd Pkts/s"]              = cnorm(200, 150, 0, 3000, n)
        rows["Bwd Pkts/s"]              = cnorm(160, 120, 0, 2500, n)
        rows["Pkt Len Min"]              = cnorm(20, 15, 0, 100, n)
        rows["Pkt Len Max"]              = cnorm(800, 400, 40, 1500, n)
        rows["Pkt Len Mean"]             = cnorm(300, 150, 0, 1500, n)
        rows["Pkt Len Std"]              = cnorm(200, 100, 0, 700, n)
        rows["FIN Flag Count"]           = rng.integers(0, 3, n)
        rows["SYN Flag Count"]           = rng.integers(0, 3, n)
        rows["RST Flag Count"]           = rng.integers(0, 2, n)
        rows["ACK Flag Count"]           = rng.integers(0, 5, n)
        rows["Down/Up Ratio"]            = cnorm(1.0, 0.4, 0, 10, n)

    elif label == "DDoS":
        rows["Flow Duration"]            = cnorm(5_000, 3_000, 0, 50_000, n)
        rows["Total Fwd Packets"]        = cnorm(200, 100, 10, 2000, n).astype(int)
        rows["Total Bwd Packets"]        = cnorm(5, 5, 0, 50, n).astype(int)
        rows["Total Length Fwd Pkts"]    = cnorm(10_000, 5_000, 0, 150_000, n)
        rows["Total Length Bwd Pkts"]    = cnorm(100, 80, 0, 1_000, n)
        rows["Fwd Pkt Len Mean"]         = cnorm(50, 20, 0, 200, n)
        rows["Bwd Pkt Len Mean"]         = cnorm(20, 10, 0, 100, n)
        rows["Flow Bytes/s"]             = cnorm(1_000_000, 500_000, 100, 5_000_000, n)
        rows["Flow Pkts/s"]              = cnorm(20_000, 10_000, 1000, 100_000, n)
        rows["Flow IAT Mean"]            = cnorm(50, 30, 0, 500, n)
        rows["Flow IAT Std"]             = cnorm(80, 50, 0, 800, n)
        rows["Fwd IAT Mean"]             = cnorm(60, 40, 0, 600, n)
        rows["Bwd IAT Mean"]             = cnorm(100, 80, 0, 1000, n)
        rows["Fwd PSH Flags"]            = rng.integers(0, 2, n)
        rows["Bwd PSH Flags"]            = np.zeros(n, dtype=int)
        rows["Fwd URG Flags"]            = rng.integers(0, 2, n)
        rows["Bwd URG Flags"]            = np.zeros(n, dtype=int)
        rows["Fwd Header Length"]        = cnorm(20, 5, 20, 40, n).astype(int)
        rows["Bwd Header Length"]        = cnorm(20, 5, 20, 40, n).astype(int)
        rows["Fwd Pkts/s"]              = cnorm(18_000, 9_000, 500, 90_000, n)
        rows["Bwd Pkts/s"]              = cnorm(500, 300, 0, 5_000, n)
        rows["Pkt Len Min"]              = cnorm(28, 10, 0, 60, n)
        rows["Pkt Len Max"]              = cnorm(80, 30, 40, 300, n)
        rows["Pkt Len Mean"]             = cnorm(54, 15, 0, 200, n)
        rows["Pkt Len Std"]              = cnorm(20, 10, 0, 80, n)
        rows["FIN Flag Count"]           = np.zeros(n, dtype=int)
        rows["SYN Flag Count"]           = rng.integers(0, 3, n)
        rows["RST Flag Count"]           = rng.integers(0, 2, n)
        rows["ACK Flag Count"]           = rng.integers(0, 3, n)
        rows["Down/Up Ratio"]            = cnorm(0.02, 0.02, 0, 0.2, n)

    elif label == "PortScan":
        rows["Flow Duration"]            = cnorm(3_000, 2_000, 0, 20_000, n)
        rows["Total Fwd Packets"]        = cnorm(3, 1, 1, 10, n).astype(int)
        rows["Total Bwd Packets"]        = cnorm(1, 1, 0, 5, n).astype(int)
        rows["Total Length Fwd Pkts"]    = cnorm(180, 60, 0, 600, n)
        rows["Total Length Bwd Pkts"]    = cnorm(40, 30, 0, 200, n)
        rows["Fwd Pkt Len Mean"]         = cnorm(60, 20, 0, 150, n)
        rows["Bwd Pkt Len Mean"]         = cnorm(40, 20, 0, 100, n)
        rows["Flow Bytes/s"]             = cnorm(60_000, 40_000, 0, 300_000, n)
        rows["Flow Pkts/s"]              = cnorm(1_000, 600, 0, 5_000, n)
        rows["Flow IAT Mean"]            = cnorm(2_000, 1_500, 0, 15_000, n)
        rows["Flow IAT Std"]             = cnorm(1_500, 1_200, 0, 10_000, n)
        rows["Fwd IAT Mean"]             = cnorm(2_000, 1_500, 0, 15_000, n)
        rows["Bwd IAT Mean"]             = cnorm(0, 0, 0, 0, n)
        rows["Fwd PSH Flags"]            = np.zeros(n, dtype=int)
        rows["Bwd PSH Flags"]            = np.zeros(n, dtype=int)
        rows["Fwd URG Flags"]            = np.zeros(n, dtype=int)
        rows["Bwd URG Flags"]            = np.zeros(n, dtype=int)
        rows["Fwd Header Length"]        = cnorm(20, 0, 20, 20, n).astype(int)
        rows["Bwd Header Length"]        = cnorm(20, 0, 20, 20, n).astype(int)
        rows["Fwd Pkts/s"]              = cnorm(800, 400, 0, 4_000, n)
        rows["Bwd Pkts/s"]              = cnorm(200, 150, 0, 1_000, n)
        rows["Pkt Len Min"]              = cnorm(20, 5, 0, 40, n)
        rows["Pkt Len Max"]              = cnorm(60, 20, 20, 200, n)
        rows["Pkt Len Mean"]             = cnorm(40, 15, 0, 150, n)
        rows["Pkt Len Std"]              = cnorm(15, 8, 0, 60, n)
        rows["FIN Flag Count"]           = rng.integers(0, 2, n)
        rows["SYN Flag Count"]           = rng.integers(1, 4, n)
        rows["RST Flag Count"]           = rng.integers(0, 3, n)
        rows["ACK Flag Count"]           = rng.integers(0, 2, n)
        rows["Down/Up Ratio"]            = cnorm(0.3, 0.3, 0, 2, n)

    elif label == "BruteForce":
        rows["Flow Duration"]            = cnorm(200_000, 100_000, 1000, 1_000_000, n)
        rows["Total Fwd Packets"]        = cnorm(50, 30, 5, 300, n).astype(int)
        rows["Total Bwd Packets"]        = cnorm(45, 28, 5, 280, n).astype(int)
        rows["Total Length Fwd Pkts"]    = cnorm(3_000, 2_000, 0, 20_000, n)
        rows["Total Length Bwd Pkts"]    = cnorm(2_500, 1_800, 0, 18_000, n)
        rows["Fwd Pkt Len Mean"]         = cnorm(60, 20, 0, 200, n)
        rows["Bwd Pkt Len Mean"]         = cnorm(55, 18, 0, 180, n)
        rows["Flow Bytes/s"]             = cnorm(20_000, 15_000, 0, 150_000, n)
        rows["Flow Pkts/s"]              = cnorm(500, 300, 0, 3_000, n)
        rows["Flow IAT Mean"]            = cnorm(3_000, 2_000, 0, 20_000, n)
        rows["Flow IAT Std"]             = cnorm(4_000, 3_000, 0, 30_000, n)
        rows["Fwd IAT Mean"]             = cnorm(3_500, 2_200, 0, 25_000, n)
        rows["Bwd IAT Mean"]             = cnorm(3_500, 2_200, 0, 25_000, n)
        rows["Fwd PSH Flags"]            = rng.integers(0, 2, n)
        rows["Bwd PSH Flags"]            = rng.integers(0, 2, n)
        rows["Fwd URG Flags"]            = np.zeros(n, dtype=int)
        rows["Bwd URG Flags"]            = np.zeros(n, dtype=int)
        rows["Fwd Header Length"]        = cnorm(40, 10, 20, 80, n).astype(int)
        rows["Bwd Header Length"]        = cnorm(40, 10, 20, 80, n).astype(int)
        rows["Fwd Pkts/s"]              = cnorm(250, 150, 0, 1_500, n)
        rows["Bwd Pkts/s"]              = cnorm(230, 140, 0, 1_400, n)
        rows["Pkt Len Min"]              = cnorm(20, 8, 0, 60, n)
        rows["Pkt Len Max"]              = cnorm(200, 80, 40, 800, n)
        rows["Pkt Len Mean"]             = cnorm(60, 20, 0, 300, n)
        rows["Pkt Len Std"]              = cnorm(40, 20, 0, 150, n)
        rows["FIN Flag Count"]           = rng.integers(0, 3, n)
        rows["SYN Flag Count"]           = rng.integers(1, 5, n)
        rows["RST Flag Count"]           = rng.integers(0, 3, n)
        rows["ACK Flag Count"]           = rng.integers(1, 6, n)
        rows["Down/Up Ratio"]            = cnorm(0.9, 0.3, 0, 3, n)

    elif label == "Botnet":
        rows["Flow Duration"]            = cnorm(500_000, 200_000, 1000, 2_000_000, n)
        rows["Total Fwd Packets"]        = cnorm(20, 10, 2, 100, n).astype(int)
        rows["Total Bwd Packets"]        = cnorm(18, 9, 2, 90, n).astype(int)
        rows["Total Length Fwd Pkts"]    = cnorm(800, 500, 0, 5_000, n)
        rows["Total Length Bwd Pkts"]    = cnorm(600, 400, 0, 4_000, n)
        rows["Fwd Pkt Len Mean"]         = cnorm(40, 15, 0, 120, n)
        rows["Bwd Pkt Len Mean"]         = cnorm(35, 12, 0, 100, n)
        rows["Flow Bytes/s"]             = cnorm(2_000, 1_500, 0, 15_000, n)
        rows["Flow Pkts/s"]              = cnorm(50, 30, 0, 300, n)
        rows["Flow IAT Mean"]            = cnorm(25_000, 15_000, 0, 150_000, n)
        rows["Flow IAT Std"]             = cnorm(30_000, 20_000, 0, 200_000, n)
        rows["Fwd IAT Mean"]             = cnorm(30_000, 18_000, 0, 200_000, n)
        rows["Bwd IAT Mean"]             = cnorm(30_000, 18_000, 0, 200_000, n)
        rows["Fwd PSH Flags"]            = rng.integers(0, 2, n)
        rows["Bwd PSH Flags"]            = rng.integers(0, 2, n)
        rows["Fwd URG Flags"]            = np.zeros(n, dtype=int)
        rows["Bwd URG Flags"]            = np.zeros(n, dtype=int)
        rows["Fwd Header Length"]        = cnorm(50, 15, 20, 100, n).astype(int)
        rows["Bwd Header Length"]        = cnorm(50, 15, 20, 100, n).astype(int)
        rows["Fwd Pkts/s"]              = cnorm(25, 15, 0, 150, n)
        rows["Bwd Pkts/s"]              = cnorm(22, 12, 0, 130, n)
        rows["Pkt Len Min"]              = cnorm(20, 8, 0, 60, n)
        rows["Pkt Len Max"]              = cnorm(150, 60, 40, 600, n)
        rows["Pkt Len Mean"]             = cnorm(40, 15, 0, 200, n)
        rows["Pkt Len Std"]              = cnorm(25, 12, 0, 100, n)
        rows["FIN Flag Count"]           = rng.integers(0, 2, n)
        rows["SYN Flag Count"]           = rng.integers(0, 2, n)
        rows["RST Flag Count"]           = rng.integers(0, 2, n)
        rows["ACK Flag Count"]           = rng.integers(0, 4, n)
        rows["Down/Up Ratio"]            = cnorm(0.9, 0.2, 0, 3, n)

    elif label == "WebAttack":
        rows["Flow Duration"]            = cnorm(80_000, 60_000, 0, 500_000, n)
        rows["Total Fwd Packets"]        = cnorm(10, 6, 1, 60, n).astype(int)
        rows["Total Bwd Packets"]        = cnorm(8, 5, 0, 50, n).astype(int)
        rows["Total Length Fwd Pkts"]    = cnorm(1_500, 1_000, 0, 10_000, n)
        rows["Total Length Bwd Pkts"]    = cnorm(5_000, 3_000, 0, 30_000, n)
        rows["Fwd Pkt Len Mean"]         = cnorm(150, 80, 0, 600, n)
        rows["Bwd Pkt Len Mean"]         = cnorm(600, 300, 0, 2_000, n)
        rows["Flow Bytes/s"]             = cnorm(30_000, 20_000, 0, 200_000, n)
        rows["Flow Pkts/s"]              = cnorm(200, 120, 0, 1_000, n)
        rows["Flow IAT Mean"]            = cnorm(8_000, 6_000, 0, 60_000, n)
        rows["Flow IAT Std"]             = cnorm(10_000, 8_000, 0, 80_000, n)
        rows["Fwd IAT Mean"]             = cnorm(10_000, 8_000, 0, 80_000, n)
        rows["Bwd IAT Mean"]             = cnorm(10_000, 8_000, 0, 80_000, n)
        rows["Fwd PSH Flags"]            = rng.integers(0, 2, n)
        rows["Bwd PSH Flags"]            = rng.integers(0, 2, n)
        rows["Fwd URG Flags"]            = np.zeros(n, dtype=int)
        rows["Bwd URG Flags"]            = np.zeros(n, dtype=int)
        rows["Fwd Header Length"]        = cnorm(50, 15, 20, 100, n).astype(int)
        rows["Bwd Header Length"]        = cnorm(50, 15, 20, 100, n).astype(int)
        rows["Fwd Pkts/s"]              = cnorm(100, 60, 0, 600, n)
        rows["Bwd Pkts/s"]              = cnorm(90, 55, 0, 500, n)
        rows["Pkt Len Min"]              = cnorm(20, 8, 0, 60, n)
        rows["Pkt Len Max"]              = cnorm(1200, 400, 100, 1500, n)
        rows["Pkt Len Mean"]             = cnorm(400, 200, 0, 1500, n)
        rows["Pkt Len Std"]              = cnorm(250, 120, 0, 700, n)
        rows["FIN Flag Count"]           = rng.integers(0, 3, n)
        rows["SYN Flag Count"]           = rng.integers(0, 2, n)
        rows["RST Flag Count"]           = rng.integers(0, 2, n)
        rows["ACK Flag Count"]           = rng.integers(0, 5, n)
        rows["Down/Up Ratio"]            = cnorm(3.0, 1.0, 0, 10, n)

    rows["Label"] = label
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Build dataset
# ---------------------------------------------------------------------------
frames = [make_class(label, n) for label, n in CLASSES.items()]
df = pd.concat(frames, ignore_index=True)

# Shuffle
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# ---------------------------------------------------------------------------
# Inject missing values (~4% of numeric cells)
# ---------------------------------------------------------------------------
numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
for col in numeric_cols:
    mask = rng.random(len(df)) < 0.04
    df.loc[mask, col] = np.nan

# ---------------------------------------------------------------------------
# Inject noise / inconsistencies (~3%)
# ---------------------------------------------------------------------------
# 1. Duplicate rows (exact duplicates)
n_dupes = int(TOTAL * 0.01)
dupe_idx = rng.choice(df.index, n_dupes, replace=False)
dupes = df.loc[dupe_idx].copy()
df = pd.concat([df, dupes], ignore_index=True)

# 2. Outlier spikes in a few columns
for col in ["Flow Bytes/s", "Flow Pkts/s", "Total Fwd Packets"]:
    spike_idx = rng.choice(df.index, int(TOTAL * 0.005), replace=False)
    df.loc[spike_idx, col] = df[col].max() * rng.uniform(5, 20, len(spike_idx))

# 3. Negative values (sensor glitch)
glitch_col = "Flow IAT Mean"
glitch_idx = rng.choice(df.index, int(TOTAL * 0.005), replace=False)
df.loc[glitch_idx, glitch_col] = -df.loc[glitch_idx, glitch_col].abs()

# Final shuffle
df = df.sample(frac=1, random_state=99).reset_index(drop=True)

# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------
out_path = Path(__file__).parent / "capstone_network_ids_dataset.csv"
df.to_csv(out_path, index=False)

print(f"Dataset saved: {out_path}")
print(f"Shape: {df.shape}")
print(f"\nClass distribution:\n{df['Label'].value_counts()}")
print(f"\nMissing values per column (top 10):\n{df.isnull().sum().sort_values(ascending=False).head(10)}")
print(f"\nData types:\n{df.dtypes}")
