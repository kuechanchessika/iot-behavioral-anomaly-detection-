"""Main entry point for IoT Network Intrusion Detection Automation.

Layer 2: AI-Powered Behavioral Anomaly Detection Pipeline
Concordia University Research Project

Renovated based on Week 8 & Week 9 Progress Updates:
- Interactive Master Menu when executed without arguments.
- Dataset Selection menu supporting SYN Flood, Benign, 50k Benchmark, 3M Full, and Custom CSVs.
- Integration with ADWIN Drift Engine, Early Stopping, and Calibrated Risk Triage.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional, Union
import pandas as pd

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import DATA_DIR, EXTERNAL_DATA_DIR, MODEL_PATH
from src.detect import IoTTrafficDetector
from src.train import train_iot_detector

# ANSI terminal colors
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


def resolve_model_path(model_arg: Optional[str]) -> Path:
    """Resolve model path from file path, filename, or known dataset alias (e.g. 'ciciot')."""
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


def run_dataset_selection_detection(
    model_path: Optional[Union[str, Path]] = None,
    threshold: Optional[float] = None,
    protocol: Optional[str] = None,
    flag: Optional[str] = None,
):
    """Interactive Dataset Selection Menu for automated batch inspection."""
    real_csv = DATA_DIR / "real_ciciot_dataset.csv"
    full_3m_csv = DATA_DIR / "real_ciciot_full_3m.csv"

    print("\n" + "=" * 65)
    print(f"{C.BOLD}{C.CYAN}   IoT DEFENDER — DATASET SELECTION & THREAT INSPECTION{C.RESET}")
    print("=" * 65)
    print("  Which dataset do you want to inspect?\n")
    print(f"  {C.RED}{C.BOLD}[1] SYN Flood Attack Dataset{C.RESET}   (DDoS — extracted attack flows)")
    print(f"  {C.GREEN}[2] Normal Traffic Only{C.RESET}        (Benign baseline telemetry only)")
    print(f"  {C.YELLOW}[3] 50,000 Benchmark Dataset{C.RESET}   (data/real_ciciot_dataset.csv)")
    if full_3m_csv.exists():
        print(f"  {C.CYAN}[4] Full 3.0 Million Dataset{C.RESET}   (data/real_ciciot_full_3m.csv)")
    print(f"  {C.WHITE}[5] Custom CSV Dataset File{C.RESET}    (provide your own path)")
    print("=" * 65)

    choice = input("  Enter choice (1-5) [default: 3]: ").strip() or "3"

    df_traffic = None
    input_desc = ""

    if choice == "1":
        print("\n[*] Loading SYN Flood attack flows from real dataset...")
        if not real_csv.exists():
            print(f"[-] Error: {real_csv} not found.")
            return
        df = pd.read_csv(real_csv, low_memory=False)
        df_traffic = df[df["label"] == "DDoS-SYN_Flood"].copy()
        input_desc = f"SYN Flood Attacks ({len(df_traffic):,} flows)"

    elif choice == "2":
        print("\n[*] Loading Benign / Normal flows from real dataset...")
        if not real_csv.exists():
            print(f"[-] Error: {real_csv} not found.")
            return
        df = pd.read_csv(real_csv, low_memory=False)
        df_traffic = df[df["label"] == "BenignTraffic"].copy()
        input_desc = f"Normal Benign Baseline ({len(df_traffic):,} flows)"

    elif choice == "4" and full_3m_csv.exists():
        print("\n[*] Loading sample of Full 3.0 Million Dataset...")
        df_traffic = pd.read_csv(full_3m_csv, nrows=50000, low_memory=False)
        input_desc = f"Full 3.0M Dataset Sample ({len(df_traffic):,} flows)"

    elif choice == "5":
        custom = input("  Enter path to your CSV file: ").strip()
        custom_path = Path(custom)
        if not custom_path.exists():
            print(f"[-] File not found: {custom}")
            return
        df_traffic = pd.read_csv(custom_path, low_memory=False)
        input_desc = f"Custom CSV: {custom_path.name} ({len(df_traffic):,} flows)"

    else:  # Default: Option 3
        print(f"\n[*] Loading Primary 50,000 Benchmark Dataset...")
        if not real_csv.exists():
            print(f"[-] Error: {real_csv} not found.")
            return
        df_traffic = pd.read_csv(real_csv, low_memory=False)
        input_desc = f"50,000 Benchmark ({len(df_traffic):,} flows)"

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

    print(f"\n[*] Inspecting {input_desc} through AI Detection Pipeline...")
    model_file = resolve_model_path(model_path)
    detector = IoTTrafficDetector(model_path=model_file, threshold=threshold)
    detector.detect_batch(traffic_data=df_traffic, save_report=True)


def run_demo():
    """Run an automated end-to-end demonstration on real physical benchmark telemetry."""
    print("\n" + "=" * 65)
    print("      IoT NETWORK INTRUSION DETECTION SYSTEM - END-TO-END DEMO")
    print("      (Physical Testbed Telemetry · UNB CIC-IoT2023 Benchmark)")
    print("=" * 65)

    real_data_path = DATA_DIR / "real_ciciot_dataset.csv"
    if not real_data_path.exists():
        print(f"[-] Benchmark dataset not found at {real_data_path}.")
        return

    # 1. Train AI model on a 10,000-flow sample
    print("\n[Step 1/2] Training AI model on real physical IoT telemetry (sample: 10,000 flows)...")
    train_iot_detector(dataset_path=real_data_path, model_type="hist_gb", sample_size=10000)

    # 2. Run automated threat detection on benchmark flows
    print("\n[Step 2/2] Running automated detection & calibrated risk triage...")
    detector = IoTTrafficDetector(model_path=MODEL_PATH)
    test_flows = pd.read_csv(real_data_path, nrows=500, low_memory=False)
    detector.detect_batch(traffic_data=test_flows, save_report=True)

    print("\n[+] Demo completed successfully! All components verified on real physical traffic.")
    print("=" * 65 + "\n")


def run_master_menu():
    """Master interactive menu displayed when main.py is run without CLI arguments."""
    while True:
        print("\n" + "=" * 65)
        print(f"{C.BOLD}{C.CYAN}       IoT DEFENDER — LAYER 2 AI ANOMALY DETECTION ENGINE{C.RESET}")
        print(f"{C.WHITE}     Concordia University · UNB CIC-IoT2023 Physical Benchmark{C.RESET}")
        print("=" * 65)
        print("  Select an action:")
        print(f"  {C.YELLOW}[1] Select Dataset to Run Threat Detection (SYN, Benign, 50k, 3M, Custom){C.RESET}")
        print(f"  {C.GREEN}[2] Interactive Behavioral Attack Simulator (5 IoT Scenarios){C.RESET}")
        print(f"  {C.CYAN}[3] ADWIN Mathematical Step-by-Step Proof (Week 8 & Week 9 Walkthrough){C.RESET}")
        print(f"  {C.WHITE}[4] Train AI Model on Dataset (Early Stopping & Youden Calibration){C.RESET}")
        print(f"  [5] Display Command-Line Help / Available Flags")
        print(f"  [6] Exit")
        print("=" * 65)

        choice = input("  Enter choice (1-6) [default: 1]: ").strip() or "1"

        if choice == "1":
            run_dataset_selection_detection()
        elif choice == "2":
            from test_interactive import run_interactive_tester
            run_interactive_tester()
        elif choice == "3":
            from test_interactive import run_adwin_walkthrough
            run_adwin_walkthrough()
        elif choice == "4":
            real_csv = DATA_DIR / "real_ciciot_dataset.csv"
            train_iot_detector(dataset_path=real_csv, model_type="hist_gb", sample_size=20000)
        elif choice == "5":
            return "help"
        elif choice in ["6", "q", "exit"]:
            print("\nExiting IoT Defender. Goodbye!")
            sys.exit(0)
        else:
            print("[-] Invalid choice. Please enter 1 to 6.")


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
        help="Path to the training dataset CSV (e.g. data/real_ciciot_dataset.csv)"
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
        help="Run threat detection (prompts dataset selection if no --input is specified)"
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
        help="Path to CSV containing network traffic to inspect (skips dataset selection menu)"
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

    # If executed with NO arguments, launch the Master Interactive Menu!
    if len(sys.argv) == 1:
        res = run_master_menu()
        if res == "help":
            parser.print_help()
        return

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

    if args.demo:
        run_demo()
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
            # Interactive dataset selection
            run_dataset_selection_detection(
                model_path=args.model_path,
                threshold=args.threshold,
                protocol=args.protocol,
                flag=args.flag
            )
            return

        # Direct file inspection when --input was explicitly provided
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
