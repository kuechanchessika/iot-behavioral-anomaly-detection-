r"""Dataset integrity checker for verifying files in D:\IoT_Data."""

import sys
from pathlib import Path

import pandas as pd

from src.config import CICIOT2023_FEATURES, EXTERNAL_DATA_DIR, TARGET_COLUMN


def inspect_dataset_directory(dir_path: Path = EXTERNAL_DATA_DIR):
    """Check if any valid CSV datasets are placed in the dataset folder."""
    print("=" * 60)
    print(f"[*] Scanning dataset directory: {dir_path}")
    print("=" * 60)

    if not dir_path.exists():
        print(f"[-] Directory {dir_path} does not exist.")
        return None

    csv_files = list(dir_path.glob("*.csv"))
    if not csv_files:
        print(f"[!] No CSV files found in {dir_path} yet.")
        print("[*] Please download a CSV from UNB CIC-IoT2023 and save it here.")
        return None

    print(f"[+] Found {len(csv_files)} CSV file(s):")
    valid_files = []
    for f in csv_files:
        size_mb = f.stat().st_size / (1024 * 1024)
        print(f"\n--- Checking File: {f.name} ({size_mb:.2f} MB) ---")

        # Read top 5 rows to verify schema
        try:
            sample_df = pd.read_csv(f, nrows=5)
            sample_df.columns = sample_df.columns.str.strip()
            cols = set(sample_df.columns)

            has_target = any(c.lower() == TARGET_COLUMN.lower() for c in cols)
            matching_features = [feat for feat in CICIOT2023_FEATURES if feat in cols]

            print(f"    Total columns in CSV   : {len(sample_df.columns)}")
            print(f"    Matching IoT features  : {len(matching_features)} / {len(CICIOT2023_FEATURES)}")
            print(f"    Target column ('label') : {'Found [OK]' if has_target else 'Missing [X]'}")

            if has_target:
                print(f"    >>> Status: READY FOR AI TRAINING! <<<")
                valid_files.append(f)
            else:
                print(f"    >>> Warning: Target label column missing. <<<")
        except Exception as e:
            print(f"    [-] Error reading file: {e}")

    print("\n" + "=" * 60)
    return valid_files


if __name__ == "__main__":
    inspect_dataset_directory()
