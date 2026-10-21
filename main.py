"""Main entry point for IoT Network Intrusion Detection Automation."""

import argparse
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import DATA_DIR, EXTERNAL_DATA_DIR, MODEL_PATH
from src.detect import IoTTrafficDetector
from src.generate_sample_data import generate_sample_iot_dataset
from src.train import train_iot_detector


def run_demo():
    """Run an automated end-to-end demonstration."""
    print("\n" + "=" * 65)
    print("      IoT NETWORK INTRUSION DETECTION SYSTEM - END-TO-END DEMO")
    print("=" * 65)

    # 1. Generate training sample
    train_path = DATA_DIR / "demo_train_dataset.csv"
    print("\n[Step 1/3] Generating synthetic training traffic (CIC-IoT2023 format)...")
    generate_sample_iot_dataset(num_samples=3000, abnormal_ratio=0.30, output_path=train_path, random_state=42)

    # 2. Train AI model
    print("\n[Step 2/3] Training AI model on training dataset...")
    train_iot_detector(dataset_path=train_path, model_type="random_forest")

    # 3. Generate new unseen traffic stream for detection
    test_stream_path = DATA_DIR / "demo_unseen_traffic.csv"
    print("\n[Step 3/3] Generating unseen incoming network traffic stream...")
    generate_sample_iot_dataset(num_samples=500, abnormal_ratio=0.40, output_path=test_stream_path, random_state=99)

    # 4. Run automated threat detection
    print("\n[Executing] Running automated detection on unseen traffic...")
    detector = IoTTrafficDetector(model_path=MODEL_PATH)
    results = detector.detect_batch(traffic_data=test_stream_path, save_report=True)

    print("\n[+] Demo completed successfully! All components verified.")
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
        "--generate-sample",
        action="store_true",
        help="Generate a synthetic sample dataset in data/ for testing"
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

    args = parser.parse_args()

    if args.test:
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

    if args.generate_sample:
        out = DATA_DIR / "sample_ciciot2023.csv"
        generate_sample_iot_dataset(num_samples=5000, output_path=out)
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

        # ── Interactive scenario menu ──────────────────────────────
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

        real_csv   = str(DATA_DIR / "real_ciciot_dataset.csv")
        benign_csv = str(DATA_DIR / "benign_only.csv")

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
            print("\n[*] Scenario: Full Mixed Dataset — 50,000 flows...")
            input_path = real_csv

        elif choice == "4":
            custom = input("  Enter path to your CSV file: ").strip()
            if not Path(custom).exists():
                print(f"[-] File not found: {custom}")
                sys.exit(1)
            input_path = custom
            print(f"\n[*] Scenario: Custom file — {input_path}")

        else:
            print("[-] Invalid choice. Defaulting to full dataset.")
            input_path = real_csv

        if not input_path:
            print("[-] Error: No input file found. Please specify with --input <path>.")
            sys.exit(1)
        # ───────────────────────────────────────────────────────────

        detector = IoTTrafficDetector(threshold=args.threshold)
        detector.detect_batch(traffic_data=input_path, save_report=True)
        return

    # If no flags passed, display help
    parser.print_help()


if __name__ == "__main__":
    main()
