"""Main entry point for IoT Network Intrusion Detection Automation.

Layer 2: AI-Powered Behavioral Anomaly Detection Pipeline
Concordia University Research Project

Renovated based on Week 8 & Week 9 Progress Updates:
- Benchmark Dataset Selection (Datasets A, B, C, D, E) matching project architecture.
- 2-Level Interactive Flow: Dataset Selection -> Scenario Selection -> Detection & Triage.
- ADWIN Drift Engine & Parameterized State Verification.
"""

import argparse
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple, Union
import pandas as pd

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import BENIGN_LABELS, DATA_DIR, EXTERNAL_DATA_DIR, MODEL_PATH
from src.detect import IoTTrafficDetector
from src.train import train_iot_detector

# ANSI terminal colors
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


# ═══════════════════════════════════════════════════════════════
# BENCHMARK DATASET REGISTRY (Datasets A - E)
# ═══════════════════════════════════════════════════════════════
BENCHMARK_DATASETS: Dict[str, Dict[str, Union[str, list, Path]]] = {
    "A": {
        "letter": "A",
        "id": "Dataset A",
        "name": "Baseline Testbed",
        "spec": "CIC-IoT2023 Local, 3.0M",
        "candidate_files": [
            DATA_DIR / "real_ciciot_full_3m.csv",
            DATA_DIR / "real_ciciot_dataset.csv",
            Path(r"D:\CSV\CSV"),
            Path(r"D:\CSV"),
        ],
        "default_file": DATA_DIR / "real_ciciot_dataset.csv",
    },
    "B": {
        "letter": "B",
        "id": "Dataset B",
        "name": "Kaggle Independent Set",
        "spec": "CIC-IoT2023 Cloud, 3.0M",
        "candidate_files": [
            DATA_DIR / "ciciot2023_kaggle.csv",
            Path(r"D:\IoT_Data"),
            DATA_DIR / "real_ciciot_dataset.csv",
        ],
        "default_file": DATA_DIR / "real_ciciot_dataset.csv",
    },
    "C": {
        "letter": "C",
        "id": "Dataset C",
        "name": "WUSTL-IIoT-2021 Benchmark",
        "spec": "Industrial SCADA, 1.2M",
        "candidate_files": [
            DATA_DIR / "wustl_iiot_2021.csv",
            Path(r"D:\Dataset\WUSTL"),
            Path(r"D:\WUSTL"),
            DATA_DIR / "real_ciciot_dataset.csv",
        ],
        "default_file": DATA_DIR / "real_ciciot_dataset.csv",
    },
    "D": {
        "letter": "D",
        "id": "Dataset D",
        "name": "UNSW ToN-IoT Testbed",
        "spec": "Smart City Sensors, 2.87M",
        "candidate_files": [
            DATA_DIR / "unsw_ton_iot.csv",
            Path(r"D:\Dataset\ToN-IoT"),
            Path(r"D:\ToN-IoT"),
            DATA_DIR / "real_ciciot_dataset.csv",
        ],
        "default_file": DATA_DIR / "real_ciciot_dataset.csv",
    },
    "E": {
        "letter": "E",
        "id": "Dataset E",
        "name": "Edge-IIoTset Benchmark",
        "spec": "MQTT/CoAP/IIoT, 157.8K",
        "candidate_files": [
            DATA_DIR / "edge_iiotset.csv",
            Path(r"D:\Dataset\Edge-IIoTset dataset"),
            DATA_DIR / "real_ciciot_dataset.csv",
        ],
        "default_file": DATA_DIR / "real_ciciot_dataset.csv",
    },
}


def resolve_model_path(model_arg: Optional[str]) -> Path:
    """Resolve model path from file path, filename, or alias."""
    if not model_arg:
        return MODEL_PATH

    p = Path(model_arg)
    if p.exists() and p.is_file():
        return p

    cand_joblib = PROJECT_ROOT / "models" / f"{model_arg}.joblib"
    if cand_joblib.exists() and cand_joblib.is_file():
        return cand_joblib

    cand_direct = PROJECT_ROOT / "models" / model_arg
    if cand_direct.exists() and cand_direct.is_file():
        return cand_direct

    return MODEL_PATH


def resolve_dataset_path(dataset_key: str) -> Tuple[Path, str]:
    """Resolve physical CSV path for selected dataset key (A-E)."""
    meta = BENCHMARK_DATASETS.get(dataset_key.upper(), BENCHMARK_DATASETS["A"])
    target_name = f"{meta['id']} ({meta['name']})"

    for candidate in meta["candidate_files"]:
        if isinstance(candidate, Path) and candidate.exists():
            if candidate.is_file() and candidate.suffix.lower() == ".csv":
                return candidate, target_name
            elif candidate.is_dir():
                csvs = list(candidate.glob("*.csv")) or list(candidate.rglob("*.csv"))
                if csvs:
                    return csvs[0], target_name

    # Fallback to local physical benchmark
    fallback = meta["default_file"]
    return fallback, target_name


def run_benchmark_dataset_selection(
    model_path: Optional[Union[str, Path]] = None,
    threshold: Optional[float] = None,
    protocol: Optional[str] = None,
    flag: Optional[str] = None,
):
    """Interactive 2-level selection flow matching the project benchmark terminal interface."""

    # ═══════════════════════════════════════════════════════════════
    # LEVEL 1: SELECT BENCHMARK DATASET (A - E)
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print(f"  {C.BOLD}{C.CYAN}IoT DEFENDER — SELECT BENCHMARK DATASET{C.RESET}")
    print("=" * 70)
    print(f"  {C.GREEN}[A]{C.RESET} Dataset A : Baseline Testbed        (CIC-IoT2023 Local, 3.0M)")
    print(f"  {C.YELLOW}[B]{C.RESET} Dataset B : Kaggle Independent Set  (CIC-IoT2023 Cloud, 3.0M)")
    print(f"  {C.CYAN}[C]{C.RESET} Dataset C : WUSTL-IIoT-2021 Benchmark (Industrial SCADA, 1.2M)")
    print(f"  {C.RED}[D]{C.RESET} Dataset D : UNSW ToN-IoT Testbed    (Smart City Sensors, 2.87M)")
    print(f"  {C.WHITE}[E]{C.RESET} Dataset E : Edge-IIoTset Benchmark  (MQTT/CoAP/IIoT, 157.8K)")
    print("=" * 70)

    dataset_choice = input("  Select Dataset (A, B, C, D, or E, default: A): ").strip().upper() or "A"
    if dataset_choice not in BENCHMARK_DATASETS:
        print(f"[*] Selection '{dataset_choice}' unrecognized. Defaulting to Dataset A.")
        dataset_choice = "A"

    dataset_file, active_target_name = resolve_dataset_path(dataset_choice)
    print(f"\n{C.GREEN}{C.BOLD}[✓] Active Target: {active_target_name}{C.RESET}")

    # ═══════════════════════════════════════════════════════════════
    # LEVEL 2: SCENARIO SELECTION FOR ACTIVE DATASET
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print(f"  {C.BOLD}{C.CYAN}IoT DEFENDER — SCENARIO SELECTION ({active_target_name}){C.RESET}")
    print("=" * 70)
    print("  Which attack scenario do you want to test?\n")
    print(f"  {C.RED}{C.BOLD}1. Attack Traffic Only{C.RESET}    (DoS / Exploits filtered from {BENCHMARK_DATASETS[dataset_choice]['id']})")
    print(f"  {C.GREEN}2. Normal Traffic Only{C.RESET}    (benign flows only)")
    print(f"  {C.YELLOW}3. Mixed — Full Dataset{C.RESET}   (all flows in {BENCHMARK_DATASETS[dataset_choice]['id']})")
    print(f"  {C.CYAN}4. Custom input file{C.RESET}      (provide your own CSV)")
    print("=" * 70)

    scenario_choice = input("  Enter choice (1-4): ").strip() or "3"

    df_traffic = None
    input_desc = ""

    if not dataset_file.exists():
        print(f"[-] Dataset file not found at: {dataset_file}")
        dataset_file = DATA_DIR / "real_ciciot_dataset.csv"
        print(f"[*] Using local benchmark file: {dataset_file}")

    if scenario_choice == "1":
        print(f"\n[*] Scenario: Attack Traffic Only — filtering attacks from {active_target_name}...")
        df_raw = pd.read_csv(dataset_file, low_memory=False)
        label_col = "label" if "label" in df_raw.columns else None
        if not label_col:
            for c in df_raw.columns:
                if c.lower() == "label":
                    label_col = c
                    break

        if label_col:
            is_attack = ~df_raw[label_col].astype(str).str.strip().str.lower().isin(BENIGN_LABELS)
            df_traffic = df_raw[is_attack].copy()
        else:
            df_traffic = df_raw.copy()
        input_desc = f"Attack Flows Only ({len(df_traffic):,} records)"
        print(f"[+] Loaded {len(df_traffic):,} attack flows.")

    elif scenario_choice == "2":
        print(f"\n[*] Scenario: Normal Traffic Only — filtering benign baseline flows...")
        df_raw = pd.read_csv(dataset_file, low_memory=False)
        label_col = "label" if "label" in df_raw.columns else None
        if not label_col:
            for c in df_raw.columns:
                if c.lower() == "label":
                    label_col = c
                    break

        if label_col:
            is_benign = df_raw[label_col].astype(str).str.strip().str.lower().isin(BENIGN_LABELS)
            df_traffic = df_raw[is_benign].copy()
        else:
            df_traffic = df_raw.copy()
        input_desc = f"Normal Benign Baseline ({len(df_traffic):,} records)"
        print(f"[+] Loaded {len(df_traffic):,} benign flows.")

    elif scenario_choice == "4":
        custom = input("  Enter path to your CSV file: ").strip()
        custom_path = Path(custom)
        if not custom_path.exists():
            print(f"[-] File not found: {custom}")
            return
        df_traffic = pd.read_csv(custom_path, low_memory=False)
        input_desc = f"Custom CSV: {custom_path.name} ({len(df_traffic):,} records)"

    else:  # Default: Option 3 (Mixed — Full Dataset)
        print(f"\n[*] Scenario: Mixed — Full Dataset ({active_target_name})...")
        df_traffic = pd.read_csv(dataset_file, low_memory=False)
        input_desc = f"Full Dataset ({len(df_traffic):,} records)"

    # Optional Protocol / Flag filtering
    if protocol:
        p_up = protocol.strip().upper()
        if p_up in df_traffic.columns:
            df_traffic = df_traffic[df_traffic[p_up] == 1.0]
        elif "Protocol Type" in df_traffic.columns:
            pmap = {"ICMP": 1, "TCP": 6, "UDP": 17}
            if p_up in pmap:
                df_traffic = df_traffic[df_traffic["Protocol Type"] == pmap[p_up]]
        print(f"[*] Filtered by protocol '{p_up}': {len(df_traffic):,} flows remain.")

    if flag:
        f_col = f"{flag.strip().lower()}_flag_number"
        if f_col in df_traffic.columns:
            df_traffic = df_traffic[df_traffic[f_col] == 1.0]
            print(f"[*] Filtered by flag '{f_col}': {len(df_traffic):,} flows remain.")

    # Execute Layer 2 AI Detection Pipeline
    print(f"\n[*] Ingesting {input_desc} into AI Anomaly Detection Pipeline...")
    model_file = resolve_model_path(model_path)
    detector = IoTTrafficDetector(model_path=model_file, threshold=threshold)
    detector.detect_batch(traffic_data=df_traffic, save_report=True)


def main():
    parser = argparse.ArgumentParser(
        description="Automated AI Network Intrusion Detection System for IoT (CIC-IoT2023)"
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run an automated end-to-end demonstration on real benchmark telemetry"
    )
    parser.add_argument(
        "--train",
        action="store_true",
        help="Train the AI model on a dataset CSV"
    )
    parser.add_argument(
        "--data",
        type=str,
        default=None,
        help="Path to training dataset CSV (e.g. data/real_ciciot_dataset.csv)"
    )
    parser.add_argument(
        "--model-type",
        type=str,
        choices=["random_forest", "hist_gb"],
        default="hist_gb",
        help="Algorithm architecture: 'hist_gb' (Histogram Gradient Boosting) or 'random_forest'"
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=None,
        help="Optional max number of records to train on"
    )
    parser.add_argument(
        "--detect",
        action="store_true",
        help="Run benchmark dataset selection and threat detection"
    )
    parser.add_argument(
        "--model-name",
        "--model-path",
        dest="model_path",
        type=str,
        default=None,
        help="Optional model filename, alias, or file path (default: models/iot_anomaly_detector.joblib)"
    )
    parser.add_argument(
        "--input",
        type=str,
        default=None,
        help="Path to CSV containing network traffic to inspect (bypasses dataset menu)"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Custom probability threshold to flag traffic as Abnormal (overrides calibrated tau*)"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Inspect external directory to verify if downloaded CSV files are ready for training"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run interactive test simulator with real IoT attack scenarios"
    )
    parser.add_argument(
        "--adwin",
        action="store_true",
        help="Run step-by-step ADWIN mathematical calculation proof (Week 8 & Week 9)"
    )
    parser.add_argument(
        "--protocol",
        type=str,
        default=None,
        help="Filter traffic by protocol (e.g. 'TCP', 'UDP', 'ICMP', 'HTTP') for testing or detection"
    )
    parser.add_argument(
        "--flag",
        type=str,
        default=None,
        help="Filter traffic by TCP flag (e.g. 'syn', 'ack', 'rst', 'fin') for testing or detection"
    )

    args = parser.parse_args()

    # 1. If executed with NO arguments, launch the Benchmark Dataset Selection by default!
    if len(sys.argv) == 1:
        run_benchmark_dataset_selection(
            model_path=args.model_path,
            threshold=args.threshold,
            protocol=args.protocol,
            flag=args.flag
        )
        return

    # 2. Direct flag handlers
    if args.adwin:
        from test_interactive import run_adwin_walkthrough
        run_adwin_walkthrough()
        return

    if args.test:
        test_target = args.data or args.input
        if test_target:
            from src.test_benchmark import run_dataset_benchmark
            run_dataset_benchmark(dataset_path=test_target, protocol=args.protocol, flag=args.flag)
            return
        from test_interactive import run_interactive_tester
        run_interactive_tester()
        return

    if args.check:
        from src.check_dataset import inspect_dataset_directory
        inspect_dataset_directory()
        return

    if args.train:
        data_path = args.data
        if not data_path:
            candidates = []
            if EXTERNAL_DATA_DIR.exists():
                candidates.extend(list(EXTERNAL_DATA_DIR.glob("*.csv")))
            candidates.extend(list(DATA_DIR.glob("*.csv")))

            if candidates:
                data_path = str(candidates[0])
                print(f"[*] No --data specified. Defaulting to found dataset: {data_path}")
            else:
                print("[-] Error: No dataset CSV found in data/. Please specify --data <path>.")
                sys.exit(1)

        train_iot_detector(
            dataset_path=data_path,
            model_type=args.model_type,
            sample_size=args.sample_size
        )
        return

    if args.detect:
        if not args.input:
            run_benchmark_dataset_selection(
                model_path=args.model_path,
                threshold=args.threshold,
                protocol=args.protocol,
                flag=args.flag
            )
            return

        # Direct CSV inspection if --input provided
        input_path = args.input
        input_p = Path(input_path)
        if input_p.is_dir():
            csv_candidates = list(input_p.glob("*.csv")) or list(input_p.rglob("*.csv"))
            if csv_candidates:
                input_path = str(csv_candidates[0])
            else:
                print(f"[-] No CSV files found in {input_p}")
                sys.exit(1)
        elif not input_p.exists():
            print(f"[-] Error: Traffic file '{input_path}' not found.")
            sys.exit(1)

        df_traffic = pd.read_csv(input_path, low_memory=False)

        if args.protocol:
            p_up = args.protocol.strip().upper()
            if p_up in df_traffic.columns:
                df_traffic = df_traffic[df_traffic[p_up] == 1.0]
            elif "Protocol Type" in df_traffic.columns:
                pmap = {"ICMP": 1, "TCP": 6, "UDP": 17}
                if p_up in pmap:
                    df_traffic = df_traffic[df_traffic["Protocol Type"] == pmap[p_up]]

        if args.flag:
            f_col = f"{args.flag.strip().lower()}_flag_number"
            if f_col in df_traffic.columns:
                df_traffic = df_traffic[df_traffic[f_col] == 1.0]

        model_file = resolve_model_path(args.model_path)
        detector = IoTTrafficDetector(model_path=model_file, threshold=args.threshold)
        detector.detect_batch(traffic_data=df_traffic, save_report=True)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
