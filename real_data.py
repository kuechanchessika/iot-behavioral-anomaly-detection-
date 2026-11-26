import sys
from pathlib import Path
import pandas as pd

# Check candidate paths for raw datasets
CANDIDATE_PATHS = [
    Path(r"D:\Dataset\CSV\CSV"),
    Path(r"D:\CSV\CSV"),
    Path(r"D:\Dataset\CSV"),
    Path(r"D:\CSV"),
    Path(r"D:\Dataset\Edge-IIoTset dataset"),
]

csv_base = None
for p in CANDIDATE_PATHS:
    if p.exists() and (p / "Benign_Final").exists():
        csv_base = p
        print(f"[+] Found dataset directory at: {csv_base}\n")
        break

if csv_base is None:
    for p in CANDIDATE_PATHS:
        if p.exists():
            csv_base = p
            print(f"[+] Found dataset directory (fallback) at: {csv_base}\n")
            break

if csv_base is None:
    print("[-] Error: Could not find dataset folder in CANDIDATE_PATHS on drive!")
    sys.exit(1)


def load_from_dir(folder_path: Path, target_count: int, label_name: str) -> pd.DataFrame:
    """Helper to load up to target_count rows across multiple CSV files in a folder."""
    print(f"[*] Loading {label_name} (Target: {target_count:,} flows)...")
    dfs = []
    total = 0
    csv_files = sorted(folder_path.glob("*.csv"))
    
    if not csv_files:
        print(f"[-] Warning: No CSVs found in {folder_path}")
        return pd.DataFrame()

    for f in csv_files:
        needed = target_count - total
        if needed <= 0:
            break
        print(f"    Reading from: {f.name} (up to {needed:,} rows)")
        try:
            df = pd.read_csv(f, nrows=needed, low_memory=False)
            dfs.append(df)
            total += len(df)
        except Exception as e:
            print(f"    [!] Error reading {f.name}: {e}")

    combined = pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()
    combined["label"] = label_name
    print(f"[+] Loaded {len(combined):,} records for {label_name}.\n")
    return combined

# ─────────────────────────────────────────────────────────────
# 1. Load ALL Normal / Benign Traffic (100% of available: ~1,100,000)
# ─────────────────────────────────────────────────────────────
df_benign = load_from_dir(csv_base / "Benign_Final", 1200000, "BenignTraffic")

# ─────────────────────────────────────────────────────────────
# 2. Load Multi-Attack Mix (Target: ~1,900,000 to reach 3,000,000)
# ─────────────────────────────────────────────────────────────
attack_targets = [
    ("Mirai-udpplain", 400000, csv_base / "Mirai-udpplain"),
    ("DDoS-SYN_Flood", 400000, csv_base / "DDoS-SYN_Flood"),
    ("DDoS-UDP_Flood", 400000, csv_base / "DDoS-UDP_Flood"),
    ("DDoS-ICMP_Flood", 350000, csv_base / "DDoS-ICMP_Flood"),
    ("DDoS-TCP_Flood", 200000, csv_base / "DDoS-TCP_Flood"),
    ("Recon-PortScan", 100000, csv_base / "Recon-PortScan"),
    ("DoS-HTTP_Flood", 100000, csv_base / "DoS-HTTP_Flood"),
]

attack_dfs = []
for label, target_n, folder in attack_targets:
    df_att = load_from_dir(folder, target_n, label)
    if not df_att.empty:
        attack_dfs.append(df_att)

if not attack_dfs:
    print("[-] Error: No attack datasets could be loaded!")
    sys.exit(1)

df_all_attacks = pd.concat(attack_dfs, ignore_index=True)

# ─────────────────────────────────────────────────────────────
# 3. Merge & Shuffle Complete 3.0 Million Multi-Attack Dataset
# ─────────────────────────────────────────────────────────────
total_rows = len(df_benign) + len(df_all_attacks)
print(f"[*] Merging and shuffling {total_rows:,} real multi-attack records...")

df_master = pd.concat([df_benign, df_all_attacks], ignore_index=True)
df_master = df_master.sample(frac=1.0, random_state=42).reset_index(drop=True)

output_path = Path("data/real_ciciot_full_3m.csv")
output_path.parent.mkdir(exist_ok=True)
df_master.to_csv(output_path, index=False)

print(f"\n[+] SUCCESS! 3.0 Million Multi-Attack Dataset saved to: {output_path} ({len(df_master):,} records)")
print("\nFinal Breakdown by Class:")
print(df_master["label"].value_counts())