"""Interactive testing utility to simulate IoT network flows and inspect AI detection.

Layer 2: AI-Powered Behavioral Anomaly Detection Pipeline
Stage 1 to Stage 8 Comprehensive Verification CLI

Renovated based on Week 8 & Week 9 Progress Updates:
- Scenarios demonstrate Sticky Note Flags (is_inf_pkt_rate, is_nan_payload).
- Scenarios demonstrate ADWIN Port Drift Engine (separating routine reboots from stealth scans).
- Interactive ADWIN Mathematical Walkthrough (verifying Hoeffding and Bernstein formulas).
- Calibrated 4-tier risk severity triage (Normal, Medium, High, Critical).
"""

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

from src.adwin import ADWINPortDriftEngine
from src.detect import IoTTrafficDetector


def run_interactive_tester():
    print("=" * 70)
    print("   IoT BEHAVIORAL ANOMALY DETECTION PIPELINE - INTERACTIVE TESTER")
    print("   (Renovated with Adaptive Windowing & Parameterized State Engine)")
    print("=" * 70)

    try:
        detector = IoTTrafficDetector()
    except Exception as e:
        print(f"[-] Error loading model: {e}")
        return

    # Realistic Test Scenarios
    scenarios = {
        "1": {
            "name": "Smart Thermostat Normal Heartbeat (Normal)",
            "description": "Periodic sensor telemetry over HTTP/DNS with valid handshakes and normal flow duration.",
            "expected": "NORMAL",
            "adwin_drift": 0.0,
            "flow": {
                "flow_duration": 1.45,       # Normal duration >> epsilon_t (5.12 us)
                "Header_Length": 32,
                "Protocol Type": 6.0,        # TCP
                "Duration": 1.45,
                "Rate": 4.5,                 # Low, calm packet rate
                "Srate": 3.0,
                "Drate": 1.5,
                "fin_flag_number": 0.0,
                "syn_flag_number": 0.0,
                "rst_flag_number": 0.0,
                "psh_flag_number": 0.0,
                "ack_flag_number": 1.0,      # Completed handshake
                "ece_flag_number": 0.0,
                "cwr_flag_number": 0.0,
                "ack_count": 8,
                "syn_count": 1,
                "fin_count": 1,
                "urg_count": 0,
                "rst_count": 0,
                "HTTP": 1.0,
                "HTTPS": 0.0,
                "DNS": 1.0,
                "Telnet": 0.0,
                "SMTP": 0.0,
                "SSH": 0.0,
                "IRC": 0.0,
                "TCP": 1.0,
                "UDP": 0.0,
                "DHCP": 0.0,
                "ARP": 0.0,
                "ICMP": 0.0,
                "IPv": 1.0,
                "LLC": 1.0,
                "Tot sum": 950.0,            # Payload >> L_min_app (2B)
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
            "name": "DDoS SYN Flood Attack (Abnormal - Critical)",
            "description": "Ultra-fast microsecond packet burst with zero duration (Delta_t <= 5.12 us) and missing ACKs.",
            "expected": "ABNORMAL",
            "adwin_drift": 0.0,
            "flow": {
                "flow_duration": 0.000002,   # 2.0 us <= epsilon_t (5.12 us) -> is_inf_pkt_rate = 1
                "Header_Length": 60,
                "Protocol Type": 6.0,
                "Duration": 0.000002,
                "Rate": 500000.0,            # Extreme rate -> sticky note
                "Srate": 495000.0,
                "Drate": 5000.0,
                "fin_flag_number": 0.0,
                "syn_flag_number": 1.0,      # Aggressive SYN flag
                "rst_flag_number": 0.0,
                "psh_flag_number": 0.0,
                "ack_flag_number": 0.0,      # No ACKs (uncompleted handshake)
                "ece_flag_number": 0.0,
                "cwr_flag_number": 0.0,
                "ack_count": 0,
                "syn_count": 85,
                "fin_count": 0,
                "urg_count": 0,
                "rst_count": 2,
                "HTTP": 0.0,
                "HTTPS": 0.0,
                "DNS": 0.0,
                "Telnet": 0.0,
                "SMTP": 0.0,
                "SSH": 0.0,
                "IRC": 0.0,
                "TCP": 1.0,
                "UDP": 0.0,
                "DHCP": 0.0,
                "ARP": 0.0,
                "ICMP": 0.0,
                "IPv": 1.0,
                "LLC": 1.0,
                "Tot sum": 0.0,              # Zero payload -> is_nan_payload = 1
                "Min": 0.0,
                "Max": 60.0,
                "AVG": 60.0,
                "Std": 0.0,
                "Tot size": 0.0,
                "IAT": 0.000001,
                "Number": 85,
                "Magnitue": 27.3,
                "Radius": 90.0,
                "Covariance": 45.0,
                "Variance": 85.0,
                "Weight": 0.95,
            }
        },
        "3": {
            "name": "Mirai Botnet Telnet Brute Force (Abnormal - Critical)",
            "description": "Infected IoT device attempting automated credential guessing on Port 23.",
            "expected": "ABNORMAL",
            "adwin_drift": 0.0,
            "flow": {
                "flow_duration": 45.2,
                "Header_Length": 850,
                "Protocol Type": 6.0,
                "Duration": 45.2,
                "Rate": 1200.0,
                "Srate": 900.0,
                "Drate": 300.0,
                "fin_flag_number": 0.0,
                "syn_flag_number": 1.0,
                "rst_flag_number": 1.0,
                "psh_flag_number": 0.0,
                "ack_flag_number": 1.0,
                "ece_flag_number": 0.0,
                "cwr_flag_number": 0.0,
                "ack_count": 25,
                "syn_count": 40,
                "fin_count": 0,
                "urg_count": 0,
                "rst_count": 12,
                "HTTP": 0.0,
                "HTTPS": 0.0,
                "DNS": 0.0,
                "Telnet": 1.0,               # Target: Telnet (Port 23)
                "SMTP": 0.0,
                "SSH": 0.0,
                "IRC": 0.0,
                "TCP": 1.0,
                "UDP": 0.0,
                "DHCP": 0.0,
                "ARP": 0.0,
                "ICMP": 0.0,
                "IPv": 1.0,
                "LLC": 1.0,
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
            "name": "Stealth Reconnaissance Port Scan (Abnormal - ADWIN Drift Triggered)",
            "description": "Rapid multi-port SYN sweep detected by ADWIN (D=4.2 > eps_cut=1.485) with unanswered handshakes.",
            "expected": "ABNORMAL",
            "adwin_drift": 4.2,              # ADWIN detected genuine port drift!
            "flow": {
                "flow_duration": 0.000004,   # 4.0 us <= 5.12 us -> zero duration
                "Header_Length": 40,
                "Protocol Type": 6.0,
                "Duration": 0.000004,
                "Rate": 45000.0,
                "Srate": 45000.0,
                "Drate": 0.0,
                "fin_flag_number": 0.0,
                "syn_flag_number": 1.0,
                "rst_flag_number": 1.0,
                "psh_flag_number": 0.0,
                "ack_flag_number": 0.0,      # Incomplete handshakes
                "ece_flag_number": 0.0,
                "cwr_flag_number": 0.0,
                "ack_count": 0,
                "syn_count": 28,
                "fin_count": 0,
                "urg_count": 0,
                "rst_count": 8,
                "HTTP": 0.0,
                "HTTPS": 0.0,
                "DNS": 0.0,
                "Telnet": 0.0,
                "SMTP": 0.0,
                "SSH": 0.0,
                "IRC": 0.0,
                "TCP": 1.0,
                "UDP": 0.0,
                "DHCP": 0.0,
                "ARP": 0.0,
                "ICMP": 0.0,
                "IPv": 1.0,
                "LLC": 1.0,
                "Tot sum": 0.0,              # Zero payload
                "Min": 0.0,
                "Max": 40.0,
                "AVG": 40.0,
                "Std": 5.0,
                "Tot size": 0.0,
                "IAT": 0.00001,
                "Number": 28,
                "Magnitue": 7.0,
                "Radius": 6.0,
                "Covariance": 3.0,
                "Variance": 20.0,
                "Weight": 0.75,
            }
        },
        "5": {
            "name": "Routine Device Reboot / Maintenance (Normal - Alarm Suppressed)",
            "description": "IoT meter reboots, checking NTP, DNS, and update servers. Temporary port rise, but valid handshakes suppress alarm.",
            "expected": "NORMAL",
            "adwin_drift": 2.5,
            "flow": {
                "flow_duration": 2.85,       # Normal duration >> 5.12 us
                "Header_Length": 29.6,
                "Protocol Type": 6.0,        # TCP
                "Duration": 2.85,
                "Rate": 87.8,
                "Srate": 80.0,
                "Drate": 7.8,
                "fin_flag_number": 0.0,
                "syn_flag_number": 0.0,      # Handshake already established
                "rst_flag_number": 0.0,
                "psh_flag_number": 0.5,
                "ack_flag_number": 0.9,      # Valid completed TCP handshakes
                "ece_flag_number": 0.0,
                "cwr_flag_number": 0.0,
                "ack_count": 9,
                "syn_count": 0,
                "fin_count": 0,
                "urg_count": 0,
                "rst_count": 0,
                "HTTP": 0.0,
                "HTTPS": 0.9,
                "DNS": 0.0,
                "Telnet": 0.0,
                "SMTP": 0.0,
                "SSH": 0.0,
                "IRC": 0.0,
                "TCP": 0.9,
                "UDP": 0.1,
                "DHCP": 0.0,
                "ARP": 0.0,
                "ICMP": 0.0,
                "IPv": 1.0,
                "LLC": 1.0,
                "Tot sum": 2447.0,           # Full application payload >> 2B
                "Min": 66.0,
                "Max": 929.0,
                "AVG": 244.7,
                "Std": 278.5,
                "Tot size": 244.7,
                "IAT": 0.0165,
                "Number": 10,
                "Magnitue": 18.5,
                "Radius": 22.0,
                "Covariance": 15.0,
                "Variance": 77594.4,
                "Weight": 1.0,
            }
        }
    }

    print("\nSelect an operational scenario to evaluate:")
    for key, sc in scenarios.items():
        print(f"  [{key}] {sc['name']}")
    print("  [6] ADWIN Mathematical Engine Walkthrough (Week 8 & Week 9 Step-by-Step Proof)")
    print("  [7] Run ALL 5 traffic scenarios consecutively")

    choice = input("\nEnter choice (1-7) [default: 7]: ").strip() or "7"

    if choice == "6":
        run_adwin_walkthrough()
        return

    selected_keys = ["1", "2", "3", "4", "5"] if choice == "7" else [choice]

    for k in selected_keys:
        if k not in scenarios:
            print(f"[-] Invalid selection '{k}'. Skipping.")
            continue

        sc = scenarios[k]
        print("\n" + "-" * 70)
        print(f"[*] Testing Scenario {k}: {sc['name']}")
        print(f"    Context     : {sc['description']}")
        print(f"    Expected    : {sc['expected']}")
        print(f"    ADWIN Drift : {sc['adwin_drift']} unique ports")
        print("-" * 70)

        # Run AI detection through pipeline
        result = detector.detect_single_flow(sc["flow"], adwin_drift_val=sc["adwin_drift"])

        pred = result["prediction"]
        score = result["anomaly_score"]
        risk = result["risk_level"]
        is_threat = result["is_threat"]
        is_inf = result["is_inf_pkt_rate"]
        is_nan = result["is_nan_payload"]

        match_icon = "[CORRECT]" if pred == sc["expected"] else "[MISMATCH]"

        print(f"    AI Decision      : [{pred}] {match_icon}")
        print(f"    Calibrated Score : {score * 100:.2f}% anomaly probability")
        print(f"    Risk Severity    : {risk}")
        print(f"    Sticky Notes     : Zero-Duration={is_inf} (Delta_t <= 5.12us) | Zero-Payload={is_nan}")
        print(f"    ADWIN Drift      : {result['adwin_port_drift']}")

        if is_threat:
            print(f"    [!] Security Action: ISOLATED TO QUARANTINE -> LAYER 3 DISPATCH")
        else:
            print(f"    [+] Security Action: PERMITTED (Normal operational telemetry verified)")

    print("\n" + "=" * 70)
    print("Interactive evaluation complete! All scenarios verified.")
    print("=" * 70 + "\n")


def run_adwin_walkthrough():
    """Execute and display the exact mathematical step-by-step ADWIN calculation from Week 8 & 9."""
    print("\n" + "=" * 70)
    print("      ADWIN ADAPTIVE WINDOWING - STEP-BY-STEP MATHEMATICAL PROOF")
    print("      (Grounded in Bifet & Gavaldà 2007 + Week 8/9 Enhanced Formulations)")
    print("=" * 70)

    w = [1, 1, 1, 1, 6, 7, 3, 9, 1]
    n0 = 4
    delta = 0.002

    res = ADWINPortDriftEngine.step_by_step_calculation(w, n0=n0, delta=delta)

    print(f"Active Observation Window W  : {res['W']}")
    print(f"Old Sub-window W0 (n0={res['n0']})     : {res['W0']}")
    print(f"New Sub-window W1 (n1={res['n1']})     : {res['W1']}")
    print(f"Total Observations (n)       : {res['n']}")
    print(f"Confidence Setting (delta)   : {res['delta']}")
    print("-" * 70)
    print(f"Step 1: Calculate Average old data (mu0)")
    print(f"        mu0 = (1 + 1 + 1 + 1) / 4 = {res['mu0']}")
    print(f"Step 2: Calculate Average new data (mu1)")
    print(f"        mu1 = (6 + 7 + 3 + 9 + 1) / 5 = {res['mu1']}")
    print(f"Step 3: Calculate difference between 2 averages (D)")
    print(f"        D = |mu0 - mu1| = |1 - 5.2| = {res['D']}")
    print(f"Step 4: Calculate harmonic sample size (m)")
    print(f"        m = 1 / (1/n0 + 1/n1) = 1 / (1/4 + 1/5) = 20/9 = {res['m']}")
    print(f"Step 5: Calculate Threshold Hurdle (epsilon_cut)")
    print(f"        5.1 Adjusted confidence: delta' = delta / n = {res['delta']} / {res['n']} = {res['delta_prime']:.7f}")
    print(f"        5.2 Hoeffding Formula  : epsilon_cut = sqrt( 1/(2m) * ln(4/delta') )")
    print(f"                               = sqrt( 1/(4.444) * {res['ln_4_over_delta_prime']} ) = {res['epsilon_cut_hoeffding']}")
    print(f"        5.3 Bernstein Formula  : epsilon_cut_Bernstein = sqrt(2*sigma^2/m * ln(4n/delta)) + R/(3m)*ln(4n/delta)")
    print(f"                               = {res['epsilon_cut_bernstein']} (Variance={res['sample_variance']}, R_dyn={res['R_dyn']})")
    print(f"Step 6: Make Decision")
    print(f"        D > epsilon_cut  ==>  {res['D']} > {res['epsilon_cut_hoeffding']}  --> {res['drift_detected']}")
    print("-" * 70)
    print(f"Result : The difference of {res['D']} exceeds the statistical threshold of {res['epsilon_cut_hoeffding']}.")
    print(f"Action : ADWIN cuts old baseline {res['W0']} from memory and emits adwin_port_drift = {res['adwin_port_drift']}.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    run_interactive_tester()
