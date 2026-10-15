"""Interactive testing utility to simulate IoT network flows and inspect AI detection."""

import sys
from pathlib import Path

# Configure utf-8 encoding for Windows terminals
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detect import IoTTrafficDetector


def run_interactive_tester():
    print("=" * 65)
    print("       IoT TRAFFIC ANOMALY DETECTION - INTERACTIVE TESTER")
    print("=" * 65)

    try:
        detector = IoTTrafficDetector()
    except Exception as e:
        print(f"[-] Error loading model: {e}")
        return

    # Realistic Test Scenarios
    scenarios = {
        "1": {
            "name": "Smart Thermostat Normal Heartbeat (Normal)",
            "description": "Periodic sensor temperature update to home gateway via HTTP/DNS",
            "expected": "NORMAL",
            "flow": {
                "flow_duration": 1.45,
                "Header_Length": 32,
                "Protocol Type": 6.0,  # TCP
                "Duration": 1.45,
                "Rate": 4.5,           # Low, calm packet rate
                "Srate": 3.0,
                "Drate": 1.5,
                "syn_flag_number": 0.0,
                "ack_flag_number": 1.0,
                "syn_count": 1,
                "ack_count": 8,
                "rst_count": 0,
                "HTTP": 1.0,
                "HTTPS": 0.0,
                "DNS": 1.0,
                "Telnet": 0.0,
                "SSH": 0.0,
                "Tot sum": 950.0,
                "Min": 48.0,
                "Max": 180.0,
                "AVG": 85.0,
                "Std": 25.0,
                "Tot size": 950.0,
                "IAT": 0.15,
                "Number": 8,
                "Magnitue": 9.2,
                "Radius": 12.5,
                "Covariance": 2.1,
                "Variance": 15.0,
                "Weight": 0.5,
            }
        },
        "2": {
            "name": "SYN Flood DDoS Attack (Abnormal)",
            "description": "Massive burst flood of spoofed SYN packets designed to exhaust memory",
            "expected": "ABNORMAL",
            "flow": {
                "flow_duration": 0.005,  # Ultra-fast microburst
                "Header_Length": 60,
                "Protocol Type": 6.0,
                "Duration": 0.005,
                "Rate": 15000.0,         # Extreme high packet rate
                "Srate": 14500.0,
                "Drate": 500.0,
                "syn_flag_number": 1.0,  # Aggressive SYN flag
                "ack_flag_number": 0.0,
                "syn_count": 85,         # Heavy SYN count without ACKs
                "ack_count": 0,
                "rst_count": 2,
                "HTTP": 0.0,
                "HTTPS": 0.0,
                "DNS": 0.0,
                "Telnet": 0.0,
                "SSH": 0.0,
                "Tot sum": 25000.0,
                "Min": 60.0,
                "Max": 1500.0,
                "AVG": 750.0,
                "Std": 180.0,
                "Tot size": 25000.0,
                "IAT": 0.0001,
                "Number": 85,
                "Magnitue": 27.3,
                "Radius": 90.0,
                "Covariance": 45.0,
                "Variance": 85.0,
                "Weight": 0.95,
            }
        },
        "3": {
            "name": "Mirai Botnet Telnet Brute Force (Abnormal)",
            "description": "Infected IoT device attempting automated credential guessing on Port 23",
            "expected": "ABNORMAL",
            "flow": {
                "flow_duration": 45.2,   # Long persistent brute connection
                "Header_Length": 850,
                "Protocol Type": 6.0,
                "Duration": 45.2,
                "Rate": 1200.0,
                "Srate": 900.0,
                "Drate": 300.0,
                "syn_flag_number": 1.0,
                "ack_flag_number": 1.0,
                "syn_count": 40,
                "ack_count": 25,
                "rst_count": 12,
                "HTTP": 0.0,
                "HTTPS": 0.0,
                "DNS": 0.0,
                "Telnet": 1.0,           # Target: Telnet protocol
                "SSH": 0.0,
                "Tot sum": 18500.0,
                "Min": 54.0,
                "Max": 1200.0,
                "AVG": 450.0,
                "Std": 140.0,
                "Tot size": 18500.0,
                "IAT": 0.02,
                "Number": 55,
                "Magnitue": 21.2,
                "Radius": 70.0,
                "Covariance": 28.0,
                "Variance": 65.0,
                "Weight": 0.88,
            }
        },
        "4": {
            "name": "Reconnaissance Port Scanner (Abnormal)",
            "description": "Attacker rapidly scanning IoT device ports looking for vulnerabilities",
            "expected": "ABNORMAL",
            "flow": {
                "flow_duration": 0.08,
                "Header_Length": 40,
                "Protocol Type": 6.0,
                "Duration": 0.08,
                "Rate": 450.0,
                "Srate": 450.0,
                "Drate": 0.0,
                "syn_flag_number": 1.0,
                "ack_flag_number": 0.0,
                "syn_count": 28,
                "ack_count": 0,
                "rst_count": 8,
                "HTTP": 0.0,
                "HTTPS": 0.0,
                "DNS": 0.0,
                "Telnet": 0.0,
                "SSH": 0.0,
                "Tot sum": 3200.0,
                "Min": 40.0,
                "Max": 80.0,
                "AVG": 50.0,
                "Std": 12.0,
                "Tot size": 3200.0,
                "IAT": 0.003,
                "Number": 28,
                "Magnitue": 7.0,
                "Radius": 6.0,
                "Covariance": 3.0,
                "Variance": 20.0,
                "Weight": 0.75,
            }
        }
    }

    print("\nSelect a test scenario to evaluate:")
    for key, sc in scenarios.items():
        print(f"  [{key}] {sc['name']}")
    print("  [5] Run ALL 4 test scenarios consecutively")

    choice = input("\nEnter choice (1-5) [default: 5]: ").strip() or "5"

    selected_keys = ["1", "2", "3", "4"] if choice == "5" else [choice]

    for k in selected_keys:
        if k not in scenarios:
            print(f"[-] Invalid selection '{k}'. Skipping.")
            continue

        sc = scenarios[k]
        print("\n" + "-" * 65)
        print(f"[*] Testing Scenario {k}: {sc['name']}")
        print(f"    Context : {sc['description']}")
        print(f"    Expected: {sc['expected']}")
        print("-" * 65)

        # Run AI detection
        result = detector.detect_single_flow(sc["flow"])

        pred = result["prediction"]
        score = result["anomaly_score"]
        risk = result["risk_level"]

        is_threat = result["is_threat"]
        match_icon = "[CORRECT]" if pred == sc["expected"] else "[MISMATCH]"

        print(f"    AI Decision     : [{pred}] {match_icon}")
        print(f"    Anomaly Score   : {score * 100:.2f}% probability of threat")
        print(f"    Risk Severity   : {risk}")

        if is_threat:
            print(f"    [!] Security Action: ISOLATED & ALERT TRIGGERED")
        else:
            print(f"    [+] Security Action: ALLOWED (Normal traffic permitted)")

    print("\n" + "=" * 65)
    print("Test finished! All traffic flows evaluated.")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    run_interactive_tester()
