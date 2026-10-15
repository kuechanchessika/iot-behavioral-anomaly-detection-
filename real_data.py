import pandas as pd
from pathlib import Path

csv_base = Path("/Users/chhanun/OneDrive - Cambodia Academy of Digital Technology/Helps/CSV")

print("[*] Loading Real Normal Traffic from local disk...")
benign_file = Path("/Users/chhanun/Projects/real_csv/benign.csv")
df_benign = pd.read_csv(benign_file, nrows=25000)
df_benign["label"] = "BenignTraffic"  # Label: 0 (Normal)

print("[*] Loading Real Attack Traffic from local disk...")
attack_file = Path("/Users/chhanun/Projects/real_csv/attack.csv")
df_attack = pd.read_csv(attack_file, nrows=25000)
df_attack["label"] = "DDoS-SYN_Flood"  # Label: 1 (Malware)

print("[*] Merging and shuffling 50,000 real records...")
df_combined = pd.concat([df_benign, df_attack], ignore_index=True)
df_combined = df_combined.sample(frac=1.0, random_state=42).reset_index(drop=True)

output_path = Path("data/real_ciciot_dataset.csv")
output_path.parent.mkdir(exist_ok=True)
df_combined.to_csv(output_path, index=False)
print(f"[+] SUCCESS! Real dataset saved to: {output_path} ({len(df_combined):,} records)")
