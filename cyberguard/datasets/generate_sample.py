"""Generate a deterministic *synthetic test fixture* with CICIDS-like columns.

This output is not CICIDS2017, cannot establish detection accuracy, and is
explicitly marked ``training_approved: false`` in ``manifest.json``.
"""

import numpy as np
import pandas as pd
from pathlib import Path

def generate_sample_dataset(output_path: Path, num_samples: int = 2000):
    np.random.seed(42)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # 80% Benign, 10% DDoS, 5% PortScan, 5% Bot
    num_benign = int(num_samples * 0.80)
    num_ddos = int(num_samples * 0.10)
    num_portscan = int(num_samples * 0.05)
    num_bot = int(num_samples * 0.05)
    
    # Feature 1: Flow Duration
    benign_duration = np.random.exponential(scale=500000, size=num_benign)
    ddos_duration = np.random.exponential(scale=10000, size=num_ddos)
    portscan_duration = np.random.exponential(scale=5000, size=num_portscan)
    bot_duration = np.random.exponential(scale=1200000, size=num_bot)
    
    # Feature 2: Flow Packets/s
    benign_pkts = np.random.normal(loc=100, scale=30, size=num_benign)
    ddos_pkts = np.random.normal(loc=50000, scale=10000, size=num_ddos)
    portscan_pkts = np.random.normal(loc=2000, scale=500, size=num_portscan)
    bot_pkts = np.random.normal(loc=50, scale=10, size=num_bot)
    
    # Feature 3: SYN Flag Count
    benign_syn = np.random.binomial(n=1, p=0.05, size=num_benign)
    ddos_syn = np.random.binomial(n=1, p=0.95, size=num_ddos)
    portscan_syn = np.random.binomial(n=1, p=0.80, size=num_portscan)
    bot_syn = np.random.binomial(n=1, p=0.10, size=num_bot)
    
    # Feature 4: Init_Win_bytes_fwd
    benign_win = np.random.normal(loc=8192, scale=1000, size=num_benign)
    ddos_win = np.random.normal(loc=256, scale=50, size=num_ddos)
    portscan_win = np.random.normal(loc=1024, scale=100, size=num_portscan)
    bot_win = np.random.normal(loc=65535, scale=10, size=num_bot)
    
    # Combine
    durations = np.concatenate([benign_duration, ddos_duration, portscan_duration, bot_duration])
    pkts = np.concatenate([benign_pkts, ddos_pkts, portscan_pkts, bot_pkts])
    syns = np.concatenate([benign_syn, ddos_syn, portscan_syn, bot_syn])
    wins = np.concatenate([benign_win, ddos_win, portscan_win, bot_win])
    
    labels = ["BENIGN"] * num_benign + ["DDoS"] * num_ddos + ["PortScan"] * num_portscan + ["Bot"] * num_bot
    
    df = pd.DataFrame({
        "Flow Duration": np.maximum(1, durations),
        "Flow Packets/s": np.maximum(0, pkts),
        "SYN Flag Count": syns,
        "Init_Win_bytes_fwd": np.maximum(0, wins),
        "Total Fwd Packets": np.random.randint(1, 50, size=num_samples),
        "Total Backward Packets": np.random.randint(0, 40, size=num_samples),
        "Flow Bytes/s": np.random.exponential(scale=50000, size=num_samples),
        "Label": labels
    })
    
    # Shuffle dataframe
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(output_path, index=False)
    print(f"[✓] Generated synthetic test fixture with {len(df)} records at: {output_path}")

if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "cicids2017" / "sample_traffic.csv"
    generate_sample_dataset(out)
