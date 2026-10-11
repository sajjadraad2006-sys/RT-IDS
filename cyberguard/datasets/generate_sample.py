"""Generate the committed deterministic test fixture with CICIDS-like columns.

This output is not CICIDS2017, cannot establish detection accuracy, and is
explicitly marked ``training_approved: false`` in ``manifest.json``.

Run ``python -m cyberguard.datasets.generate_sample --check`` to prove that the
committed fixture still matches the generator under the pinned dependencies.
"""

import argparse
from pathlib import Path
import sys
import tempfile

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import numpy as np
import pandas as pd

from backend.detection.features import FEATURE_NAMES


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
    
    # Combine the class-shaped values into a complete canonical 32-feature
    # upload contract. These deterministic relationships are fixture mechanics,
    # not a claim that the rows reproduce a real capture distribution.
    durations = np.concatenate([benign_duration, ddos_duration, portscan_duration, bot_duration])
    pkts = np.concatenate([benign_pkts, ddos_pkts, portscan_pkts, bot_pkts])
    syns = np.concatenate([benign_syn, ddos_syn, portscan_syn, bot_syn])
    wins = np.concatenate([benign_win, ddos_win, portscan_win, bot_win])
    fwd_packets = rng.randint(1, 50, size=num_samples)
    bwd_packets = rng.randint(0, 40, size=num_samples)
    fwd_lengths = rng.uniform(40, 1400, size=num_samples)
    bwd_lengths = rng.uniform(40, 1400, size=num_samples)
    fwd_bytes = fwd_packets * fwd_lengths
    bwd_bytes = bwd_packets * bwd_lengths
    total_packets = fwd_packets + bwd_packets
    total_bytes = fwd_bytes + bwd_bytes
    seconds = np.maximum(durations / 1e6, 1e-9)
    packet_mean = total_bytes / np.maximum(total_packets, 1)
    packet_min = np.minimum(fwd_lengths, bwd_lengths)
    packet_max = np.maximum(fwd_lengths, bwd_lengths)
    packet_std = np.abs(fwd_lengths - bwd_lengths) / 2

    labels = ["BENIGN"] * num_benign + ["DDoS"] * num_ddos + ["PortScan"] * num_portscan + ["Bot"] * num_bot

    values = {
        "flow_duration": np.maximum(1, durations),
        "total_fwd_packets": fwd_packets,
        "total_bwd_packets": bwd_packets,
        "total_fwd_bytes": fwd_bytes,
        "total_bwd_bytes": bwd_bytes,
        "packets_per_sec": np.maximum(0, pkts),
        "bytes_per_sec": total_bytes / seconds,
        "fwd_packet_length_mean": fwd_lengths,
        "bwd_packet_length_mean": bwd_lengths,
        "packet_length_mean": packet_mean,
        "packet_length_std": packet_std,
        "packet_length_max": packet_max,
        "packet_length_min": packet_min,
        "avg_pkt_size": packet_mean,
        "syn_flag_count": syns,
        "ack_flag_count": rng.binomial(1, 0.75, size=num_samples),
        "rst_flag_count": rng.binomial(1, 0.03, size=num_samples),
        "fin_flag_count": rng.binomial(1, 0.2, size=num_samples),
        "psh_flag_count": rng.binomial(1, 0.15, size=num_samples),
        "urg_flag_count": np.zeros(num_samples, dtype=int),
        "init_win_bytes_fwd": np.maximum(0, wins),
        "init_win_bytes_bwd": rng.randint(0, 65536, size=num_samples),
        "flow_iat_mean": durations / np.maximum(total_packets, 1),
        "flow_iat_std": durations / np.maximum(total_packets, 1) * 0.2,
        "flow_iat_max": durations / np.maximum(total_packets, 1) * 1.5,
        "fwd_iat_mean": durations / np.maximum(fwd_packets, 1),
        "fwd_header_len": fwd_packets * 20,
        "bwd_header_len": bwd_packets * 20,
        "down_up_ratio": bwd_bytes / np.maximum(fwd_bytes, 1e-9),
        "flow_bytes_ratio": fwd_bytes / np.maximum(total_bytes, 1e-9),
        "active_mean": durations * 0.7,
        "idle_mean": durations * 0.3,
    }
    df = pd.DataFrame({name: values[name] for name in FEATURE_NAMES})
    df["Label"] = labels
    
    # Shuffle dataframe
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(output_path, index=False, lineterminator="\n")
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
            if sys.platform == "win32":
                import pandas as pd
                df_gen = pd.read_csv(generated)
                df_com = pd.read_csv(args.output)
                try:
                    pd.testing.assert_frame_equal(df_gen, df_com, check_exact=False, rtol=1e-12, atol=1e-12)
                    print(f"[✓] Fixture reproducibility check passed (Windows CRT precision tolerance): {args.output}")
                    return 0
                except Exception:
                    pass
            print(f"[✗] Fixture does not match the seed-42 generator: {args.output}")
            return 1
    print(f"[✓] Fixture reproducibility check passed: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
