"""Generate the committed deterministic test fixture with CICIDS-like columns.

This output is not CICIDS2017, cannot establish detection accuracy, and is
explicitly marked ``training_approved: false`` in ``manifest.json``.

Run ``python -m cyberguard.datasets.generate_sample --check`` to prove that the
committed fixture still matches the generator under the pinned dependencies.
"""

import argparse
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd


DEFAULT_OUTPUT = Path(__file__).resolve().parent / "cicids2017" / "sample_traffic.csv"


def generate_sample_dataset(output_path: Path, num_samples: int = 2000) -> Path:
    """Write a seed-42 fixture without mutating NumPy's process-global RNG."""
    if num_samples <= 0:
        raise ValueError("num_samples must be positive")
    rng = np.random.RandomState(42)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # 80% Benign, 10% DDoS, 5% PortScan, 5% Bot
    num_benign = int(num_samples * 0.80)
    num_ddos = int(num_samples * 0.10)
    num_portscan = int(num_samples * 0.05)
    num_bot = int(num_samples * 0.05)
    
    # Feature 1: Flow Duration
    benign_duration = rng.exponential(scale=500000, size=num_benign)
    ddos_duration = rng.exponential(scale=10000, size=num_ddos)
    portscan_duration = rng.exponential(scale=5000, size=num_portscan)
    bot_duration = rng.exponential(scale=1200000, size=num_bot)
    
    # Feature 2: Flow Packets/s
    benign_pkts = rng.normal(loc=100, scale=30, size=num_benign)
    ddos_pkts = rng.normal(loc=50000, scale=10000, size=num_ddos)
    portscan_pkts = rng.normal(loc=2000, scale=500, size=num_portscan)
    bot_pkts = rng.normal(loc=50, scale=10, size=num_bot)
    
    # Feature 3: SYN Flag Count
    benign_syn = rng.binomial(n=1, p=0.05, size=num_benign)
    ddos_syn = rng.binomial(n=1, p=0.95, size=num_ddos)
    portscan_syn = rng.binomial(n=1, p=0.80, size=num_portscan)
    bot_syn = rng.binomial(n=1, p=0.10, size=num_bot)
    
    # Feature 4: Init_Win_bytes_fwd
    benign_win = rng.normal(loc=8192, scale=1000, size=num_benign)
    ddos_win = rng.normal(loc=256, scale=50, size=num_ddos)
    portscan_win = rng.normal(loc=1024, scale=100, size=num_portscan)
    bot_win = rng.normal(loc=65535, scale=10, size=num_bot)
    
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
        "Total Fwd Packets": rng.randint(1, 50, size=num_samples),
        "Total Backward Packets": rng.randint(0, 40, size=num_samples),
        "Flow Bytes/s": rng.exponential(scale=50000, size=num_samples),
        "Label": labels
    })
    
    # Shuffle dataframe
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(output_path, index=False)
    print(f"[✓] Generated synthetic test fixture with {len(df)} records at: {output_path}")
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--rows", type=int, default=2000)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate in a temporary directory and compare exact bytes",
    )
    args = parser.parse_args()
    if not args.check:
        generate_sample_dataset(args.output, args.rows)
        return 0

    if not args.output.is_file():
        print(f"[✗] Committed fixture is missing: {args.output}")
        return 1
    with tempfile.TemporaryDirectory(prefix="cyberguard-fixture-") as directory:
        generated = generate_sample_dataset(Path(directory) / args.output.name, args.rows)
        if generated.read_bytes() != args.output.read_bytes():
            print(f"[✗] Fixture does not match the seed-42 generator: {args.output}")
            return 1
    print(f"[✓] Fixture reproducibility check passed: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
