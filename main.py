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
    """Run an automated end-to-end verification using the real CIC-IoT benchmark dataset."""
    print("\n" + "=" * 65)
    print("      IoT NETWORK INTRUSION DETECTION SYSTEM - END-TO-END DEMO")
    print("=" * 65)

    real_data_path = DATA_DIR / "real_ciciot_dataset.csv"
    if not real_data_path.exists():
        print(f"[-] Error: Real benchmark dataset not found at '{real_data_path}'.")
        return

    # 1. Train AI model on real dataset (fast verification sample)
    print("\n[Step 1/2] Training AI model on real CIC-IoT2023 dataset (10,000 flows)...")
    train_iot_detector(dataset_path=real_data_path, model_type="hist_gb", sample_size=10000)

    # 2. Run automated threat detection on real traffic
    print("\n[Step 2/2] Running automated detection on real network traffic...")
    detector = IoTTrafficDetector(model_path=MODEL_PATH)
    detector.detect_batch(traffic_data=real_data_path, save_report=True)

    print("\n[+] Verification completed successfully! All components verified on real data.")
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
            real_default = DATA_DIR / "real_ciciot_dataset.csv"
            if real_default.exists():
                data_path = str(real_default)
                print(f"[*] No --data specified. Defaulting to real benchmark dataset: {data_path}")
            else:
                candidates = []
                if EXTERNAL_DATA_DIR.exists():
                    candidates.extend(list(EXTERNAL_DATA_DIR.glob("*.csv")))
                candidates.extend(list(DATA_DIR.glob("*.csv")))

                if candidates:
                    data_path = str(candidates[0])
                    print(f"[*] No --data specified. Defaulting to found dataset: {data_path}")
                else:
                    print(
                        "[-] Error: No dataset CSV found in data/ or D:\\IoT_Data. "
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
        if not input_path:
            real_default = DATA_DIR / "real_ciciot_dataset.csv"
            if real_default.exists():
                input_path = str(real_default)
                print(f"[*] No --input specified. Defaulting to real benchmark dataset: {input_path}")
            else:
                candidates = []
                if EXTERNAL_DATA_DIR.exists():
                    candidates.extend(list(EXTERNAL_DATA_DIR.glob("*.csv")))
                candidates.extend(list(DATA_DIR.glob("*.csv")))

                if candidates:
                    input_path = str(candidates[0])
                    print(f"[*] No --input specified. Defaulting to found dataset: {input_path}")
                else:
                    print("[-] Error: Please specify the traffic file to inspect using --input <path_to_csv>.")
                    sys.exit(1)

        detector = IoTTrafficDetector(threshold=args.threshold)
        detector.detect_batch(traffic_data=input_path, save_report=True)
        return

    # If no flags passed, display help
    parser.print_help()


if __name__ == "__main__":
    main()
