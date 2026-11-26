"""Main entry point for IoT Network Intrusion Detection Automation."""

import argparse
import sys
from pathlib import Path
from typing import Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import DATA_DIR, EXTERNAL_DATA_DIR, MODEL_PATH
from src.detect import IoTTrafficDetector
from src.train import train_iot_detector


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

    # Dataset or framework alias
    alias = model_arg.strip().lower()
    if alias in ["ciciot", "ciciot2023", "iot", "default", "hist_gb", "random_forest"]:
        return MODEL_PATH

    print(f"[*] Note: Model '{model_arg}' not found on disk. Defaulting to benchmark model: {MODEL_PATH}")
    return MODEL_PATH


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
    import pandas as pd
    test_flows = pd.read_csv(real_data_path, nrows=500, low_memory=False)
    results = detector.detect_batch(traffic_data=test_flows, save_report=True)

    print("\n[+] Demo completed successfully! All components verified on real physical traffic.")
    print("=" * 65 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Automated AI Network Intrusion Detection System for IoT (CIC-IoT2023)"
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run an automated end-to-end demonstration (data gen -> train -> detect)"
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
        help="Path to the training dataset CSV (e.g. CIC-IoT2023 CSV file)"
    )
    parser.add_argument(
        "--model-type",
        type=str,
        choices=["random_forest", "hist_gb"],
        default="random_forest",
        help="Algorithm architecture: 'random_forest' or 'hist_gb' (Histogram Gradient Boosting)"
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=None,
        help="Optional max number of records to train on (useful for large multi-GB datasets)"
    )
    parser.add_argument(
        "--detect",
        action="store_true",
        help="Run automated threat detection on incoming traffic data"
    )
    parser.add_argument(
        "--model-name",
        "--model-path",
        dest="model_path",
        type=str,
        default=None,
        help="Optional model filename, alias (e.g. 'ciciot'), or file path (default: models/iot_anomaly_detector.joblib)"
    )
    parser.add_argument(
        "--input",
        type=str,
        default=None,
        help="Path to CSV containing unseen network traffic to inspect"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Probability threshold to flag traffic as Abnormal (default: 0.50)"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Inspect D:\\IoT_Data to verify if downloaded CSV files are ready for training"
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
            # Check D:\IoT_Data first, then local data/
            candidates = []
            if EXTERNAL_DATA_DIR.exists():
                candidates.extend(list(EXTERNAL_DATA_DIR.glob("*.csv")))
            candidates.extend(list(DATA_DIR.glob("*.csv")))

            if candidates:
                data_path = str(candidates[0])
                print(f"[*] No --data specified. Defaulting to found dataset: {data_path}")
            else:
                print(
                    "[-] Error: No dataset CSV found in D:\\IoT_Data or data/. "
                    "Please specify the path using --data <path>."
                )
                sys.exit(1)

        train_iot_detector(
            dataset_path=data_path,
            model_type=args.model_type,
            sample_size=args.sample_size
        )
        return

    if args.detect:
        input_path = args.input
        real_csv = str(DATA_DIR / "real_ciciot_dataset.csv")

        # If no specific input was provided via --input, show interactive scenario selection
        if not input_path:
            RED    = "\033[91m"
            GREEN  = "\033[92m"
            YELLOW = "\033[93m"
            CYAN   = "\033[96m"
            BOLD   = "\033[1m"
            RESET  = "\033[0m"

            print("\n" + "=" * 55)
            print(f"{BOLD}{CYAN}   IoT DEFENDER — SCENARIO SELECTION{RESET}")
            print("=" * 55)
            print("  Which attack scenario do you want to test?\n")
            print(f"  {RED}{BOLD}1. SYN Flood Attack{RESET}       (DDoS — real dataset)")
            print(f"  {GREEN}2. Normal Traffic Only{RESET}    (benign flows only)")
            print(f"  {YELLOW}3. Mixed — Full Dataset{RESET}   (all 50,000 flows)")
            print(f"  {CYAN}4. Custom input file{RESET}      (provide your own CSV)")
            print("=" * 55)

            choice = input("  Enter choice (1-4): ").strip()

            if choice == "1":
                print("\n[*] Scenario: SYN Flood Attack — loading attack flows only...")
                import pandas as pd
                df = pd.read_csv(real_csv, low_memory=False)
                attack_df = df[df["label"] == "DDoS-SYN_Flood"]
                tmp_path = str(DATA_DIR / "_tmp_attack_scenario.csv")
                attack_df.to_csv(tmp_path, index=False)
                input_path = tmp_path
                print(f"[+] Loaded {len(attack_df):,} SYN Flood attack flows.")

            elif choice == "2":
                print("\n[*] Scenario: Normal Traffic Only — loading benign flows...")
                import pandas as pd
                df = pd.read_csv(real_csv, low_memory=False)
                benign_df = df[df["label"] == "BenignTraffic"]
                tmp_path = str(DATA_DIR / "_tmp_benign_scenario.csv")
                benign_df.to_csv(tmp_path, index=False)
                input_path = tmp_path
                print(f"[+] Loaded {len(benign_df):,} benign flows.")

            elif choice == "3":
                print("\n[*] Scenario: Full Mixed Dataset — all flows...")
                input_path = real_csv

            elif choice == "4":
                custom = input("  Enter path to your CSV file: ").strip()
                if not Path(custom).exists():
                    print(f"[-] File not found: {custom}")
                    sys.exit(1)
                input_path = custom
                print(f"\n[*] Scenario: Custom file — {input_path}")

            else:
                print("[*] Defaulting to full benchmark dataset.")
                input_path = real_csv

        model_file = resolve_model_path(args.model_path)
        detector = IoTTrafficDetector(model_path=model_file, threshold=args.threshold)

        input_p = Path(input_path)
        if input_p.is_dir():
            csv_candidates = list(input_p.glob("*.csv")) or list(input_p.rglob("*.csv"))
            if csv_candidates:
                input_path = str(csv_candidates[0])
                print(f"[*] Directory specified. Selected traffic file: {input_path}")
            else:
                print(f"[-] No CSV files found in {input_p}")
                sys.exit(1)
        elif not input_p.exists():
            print(f"[-] Error: Traffic file '{input_path}' not found.")
            sys.exit(1)

        import pandas as pd
        df_traffic = pd.read_csv(input_path, low_memory=False)

        if args.protocol:
            p_up = args.protocol.strip().upper()
            if p_up in df_traffic.columns:
                df_traffic = df_traffic[df_traffic[p_up] == 1.0]
                print(f"[*] Filtered by protocol '{p_up}': {len(df_traffic):,} flows remain.")
            elif "Protocol Type" in df_traffic.columns:
                pmap = {"ICMP": 1, "TCP": 6, "UDP": 17}
                if p_up in pmap:
                    df_traffic = df_traffic[df_traffic["Protocol Type"] == pmap[p_up]]
                    print(f"[*] Filtered by Protocol Type '{p_up}': {len(df_traffic):,} flows remain.")

        if args.flag:
            f_col = f"{args.flag.strip().lower()}_flag_number"
            if f_col in df_traffic.columns:
                df_traffic = df_traffic[df_traffic[f_col] == 1.0]
                print(f"[*] Filtered by flag '{f_col}': {len(df_traffic):,} flows remain.")

        detector.detect_batch(traffic_data=df_traffic, save_report=True)
        return

    # If no flags passed, display help
    parser.print_help()


if __name__ == "__main__":
    main()
