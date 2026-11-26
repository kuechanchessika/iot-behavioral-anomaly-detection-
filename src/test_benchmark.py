"""Benchmark and test module to evaluate AI detection across all CIC-IoT2023 categories."""

from pathlib import Path
from typing import Optional, Union
import numpy as np
import pandas as pd

from src.config import LOGS_DIR, MODEL_PATH
from src.detect import IoTTrafficDetector


def run_dataset_benchmark(
    dataset_path: Union[str, Path] = Path(r"D:\CSV"),
    sample_per_class: int = 200,
    protocol: Optional[str] = None,
    flag: Optional[str] = None,
):
    """Run an automated detection test against each category in the CIC-IoT dataset."""
    root = Path(dataset_path)
    if (root / "CSV").exists() and (root / "CSV" / "Benign_Final").exists():
        root = root / "CSV"

    if not root.exists() or not (root / "Benign_Final").exists():
        print(f"[-] Could not find valid CIC-IoT directory at: {root}")
        return

    detector = IoTTrafficDetector(model_path=MODEL_PATH)

    categories = sorted([d.name for d in root.iterdir() if d.is_dir()])
    print("\n" + "=" * 70)
    print("      AUTOMATED BENCHMARK EVALUATION ON NEW DATASET")
    print(f"  Root: {root} | Categories: {len(categories)}")
    if protocol:
        print(f"  Filter: Protocol = {protocol.upper()}")
    if flag:
        print(f"  Filter: TCP Flag = {flag.lower()}")
    print("=" * 70)
    print(f"{'Category Name':<28} | {'Type':<8} | {'Tested':<7} | {'Threats':<7} | {'Normal':<7} | {'Accuracy':<8}")
    print("-" * 70)

    results_summary = []
    total_benign_tested = 0
    total_benign_correct = 0
    total_attack_tested = 0
    total_attack_detected = 0

    for cat in categories:
        cat_dir = root / cat
        csv_files = list(cat_dir.glob("*.csv"))
        if not csv_files:
            continue

        try:
            df = pd.read_csv(csv_files[0], nrows=sample_per_class * 2, low_memory=False)
        except Exception:
            continue

        # Protocol filtering
        if protocol:
            p_up = protocol.strip().upper()
            if p_up in df.columns:
                df = df[df[p_up] == 1.0]
            elif "Protocol Type" in df.columns:
                pmap = {"ICMP": 1, "TCP": 6, "UDP": 17}
                if p_up in pmap:
                    df = df[df["Protocol Type"] == pmap[p_up]]

        # Flag filtering
        if flag:
            f_col = f"{flag.strip().lower()}_flag_number"
            if f_col in df.columns:
                df = df[df[f_col] == 1.0]

        if len(df) == 0:
            continue

        if len(df) > sample_per_class:
            df = df.iloc[:sample_per_class]

        res = detector.detect_batch(df, save_report=False)
        threat_count = int((res["prediction"] == "ABNORMAL").sum())
        normal_count = int((res["prediction"] == "NORMAL").sum())
        total_tested = len(res)

        is_benign = (cat == "Benign_Final" or "benign" in cat.lower())
        cat_type = "NORMAL" if is_benign else "ATTACK"

        if is_benign:
            accuracy = (normal_count / total_tested * 100) if total_tested > 0 else 0
            total_benign_tested += total_tested
            total_benign_correct += normal_count
        else:
            accuracy = (threat_count / total_tested * 100) if total_tested > 0 else 0
            total_attack_tested += total_tested
            total_attack_detected += threat_count

        status_marker = "[OK]" if accuracy >= 80 else "[WARN]"
        print(f"{cat:<28} | {cat_type:<8} | {total_tested:<7} | {threat_count:<7} | {normal_count:<7} | {accuracy:>6.1f}% {status_marker}")

        results_summary.append({
            "category": cat,
            "type": cat_type,
            "tested": total_tested,
            "threats": threat_count,
            "normal": normal_count,
            "accuracy": accuracy
        })

    # Overall Summary
    total_tested_all = total_benign_tested + total_attack_tested
    overall_acc = (
        (total_benign_correct + total_attack_detected) / total_tested_all * 100
        if total_tested_all > 0 else 0
    )
    det_rate = (total_attack_detected / total_attack_tested * 100) if total_attack_tested > 0 else 0
    fpr = ((total_benign_tested - total_benign_correct) / total_benign_tested * 100) if total_benign_tested > 0 else 0

    print("=" * 70)
    print("                     OVERALL BENCHMARK SUMMARY")
    print("=" * 70)
    print(f" Total Categories Tested       : {len(results_summary)}")
    print(f" Total Network Flows Evaluated : {total_tested_all:,}")
    print(f" Overall Classification Accuracy: {overall_acc:.2f}%")
    print(f" Attack Detection Rate (Recall): {det_rate:.2f}% ({total_attack_detected:,} / {total_attack_tested:,})")
    print(f" False Alarm Rate (FPR)        : {fpr:.2f}% ({total_benign_tested - total_benign_correct:,} / {total_benign_tested:,})")
    print("=" * 70 + "\n")

    return results_summary
