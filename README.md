# Layer 2: AI-Powered IoT Behavioral Anomaly Detection

**Research Project:** A Cross-Protocol Anomaly Detection Framework for Connected IoT Infrastructure: Mitigating Cyber-Physical Attacks on Smart Traffic and Municipal Systems  
**Institution:** Concordia University  
**Component:** Layer 2 (AI-Powered Behavioral Anomaly Detection Engine)  
**Benchmark:** Canadian Institute for Cybersecurity (**UNB CIC-IoT2023**)  

---

## 1. Project Context & The Three-Layer Security Framework

This repository houses **Layer 2** of a comprehensive three-tier cybersecurity framework designed to safeguard smart traffic lights, municipal controllers, and connected IoT infrastructure against cyber-physical intrusions:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 1: Cryptographic Authentication                                      │
│ - Verifies device identity, certificates, and token signatures.             │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (Authenticated Network Traffic)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 2: AI-Based Behavioral Anomaly Detection (THIS MODULE)                 │
│ - Ingests 46 flow features; applies Z-score scaling.                        │
│ - Calculates calibrated anomaly probabilities (0.00% to 100.00%).           │
│ - Triages threat severity (NORMAL, MEDIUM, HIGH, CRITICAL).                 │
│ - Isolates malicious flows to timestamped quarantine logs.                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (Threat Alerts & Anomaly Scores)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 3: Zero Trust Cyber-Physical Safety Validation & Mitigation           │
│ - Dynamic connection dropping, compromised sensor quarantine.               │
│ - Safe-state transition for municipal controllers (e.g. flashing yellow).   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Dataset Architecture: The Three Datasets

The repository maintains three datasets in [`data/`](file:///C:/Users/U-ser/OneDrive/Research%20Material%20Concordia/AI%20defense/data) for distinct stages of development, verification, and academic evaluation:

| Dataset File | Records | Normal Flows | Attack Flows | Source / Origin | Purpose |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **`real_ciciot_dataset.csv`** | **50,000** | 25,000 (50.0%) | 25,000 (50.0%) | **Physical Testbed:** Official UNB CIC-IoT2023 benchmark recorded from 105 real physical IoT devices. | **Primary Academic Benchmark:** Ground-truth training and thesis performance evaluation. |
| **`demo_train_dataset.csv`** | **3,000** | 2,100 (70.0%) | 900 (30.0%) | **Local Generator:** Synthetic data from `src/generate_sample_data.py` (seed 42). | **Rapid Pipeline Demo:** Tests training code execution in under 1 second. |
| **`demo_unseen_traffic.csv`** | **500** | 238 (47.6%) | 262 (52.4%) | **Local Generator:** Synthetic data from `src/generate_sample_data.py` (seed 99). | **Live Stream Simulation:** Simulates brand new, unseen traffic to evaluate real-time alert isolation. |

---

## 3. Repository Directory Structure

```
AI defense/
│
├── data/                                    # Training datasets & incoming traffic streams
│   ├── real_ciciot_dataset.csv              # 50,000 real physical testbed records (Benchmark)
│   ├── demo_train_dataset.csv               # 3,000 synthetic training records (Demo)
│   └── demo_unseen_traffic.csv              # 500 unseen simulated incoming records (Test)
│
├── models/                                  # Trained AI model weights & evaluation metadata
│   ├── iot_anomaly_detector.joblib          # Serialized pipeline (Scaler + Trained Model)
│   └── model_metadata.json                  # Performance metrics, feature schema & timestamp
│
├── logs/                                    # Automated forensic audit & alert quarantine records
│   ├── detection_log_*.csv                  # Full audit log of all inspected network flows
│   └── alerts_*.csv                         # Isolated threat alerts passed to Layer 3
│
├── src/                                     # Core engine source code
│   ├── config.py                            # Central paths, 46-feature schema, alert threshold
│   ├── preprocess.py                        # Imputation, label encoding, Z-score scaling
│   ├── train.py                             # HistGradientBoosting / Random Forest training pipeline
│   ├── detect.py                            # Real-time probability scoring & 4-tier risk triage
│   └── generate_sample_data.py              # Synthetic CIC-IoT2023 data generator
│
├── test_interactive.py                      # Interactive attack scenario simulator CLI
├── main.py                                  # Unified Command-Line Interface (CLI)
├── real_data.py                             # Extractor script for 50,000 real CIC-IoT benchmark
├── AI_TRAINING_AND_DETECTION_REPORT.md      # Comprehensive research & technical report
├── PROGRESS_REPORT.md                       # Phase 1 milestone progress report
├── requirements.txt                         # Python dependencies
└── README.md                                # Project documentation
```

---

## 4. Detection Mechanics, Formulas & Standards

### 4.1 Feature Ingestion & Normalization
* **46 Standard CIC-IoT2023 Features:** Flow timing (`flow_duration`, `Rate`, `Srate`, `Drate`), TCP flags (`syn_flag_number`, `ack_flag_number`, `syn_count`, `rst_count`), protocol indicators (`HTTP`, `HTTPS`, `DNS`, `Telnet`, `SSH`), and statistical moments (`Tot sum`, `Min`, `Max`, `AVG`, `Std`, `Variance`).
* **Z-Score Normalization Formula (`src/preprocess.py`):**
  $$z = \frac{x - \mu}{\sigma}$$
  Prevents high-magnitude metrics (e.g. byte volume) from mathematically overpowering critical 1-bit flags (e.g. SYN flag).

### 4.2 Probability Estimation Formula
* **Algorithm:** Histogram-Based Gradient Boosting (`HistGradientBoostingClassifier`, 150 decision tree stages).
* **Logistic Sigmoid Function (`src/detect.py`):**
  $$P(\text{Attack} \mid x) = \frac{1}{1 + e^{-F(x)}}$$
  Computes a continuous **Anomaly Score** between **$0.0000$ and $1.0000$** ($0.0\%$ to $100.0\%$).

### 4.3 4-Tier Severity Triage Standard (NIST SP 800-61 / CVSS)
The anomaly score is categorized into standardized incident severity tiers:

```python
def get_risk(score: float) -> str:
    if score >= 0.90:
        return "CRITICAL"   # Score >= 90%: Immediate quarantine & Layer 3 isolation
    elif score >= 0.75:
        return "HIGH"       # Score 75% - 89%: Warning alert & priority inspection
    elif score >= 0.50:
        return "MEDIUM"     # Score 50% - 74%: Mild anomaly flagged for observation
    return "NORMAL"         # Score < 50%: Benign routine sensor telemetry
```

* **Global Alert Threshold:** `ALERT_THRESHOLD = 0.50` ([`src/config.py`](file:///C:/Users/U-ser/OneDrive/Research%20Material%20Concordia/AI%20defense/src/config.py#L51)). Flows scoring $\ge 50\%$ are flagged as `is_abnormal = 1` and automatically exported to `logs/alerts_*.csv`.

---

## 5. How to Run and Test

First, navigate to the project directory in PowerShell:

```powershell
cd "C:\Users\U-ser\OneDrive\Research Material Concordia\AI defense"
```

### Method 1: Interactive Attack Scenario Simulator (Recommended)
Simulate specific IoT behaviors and cyberattacks one by one:

```powershell
.\.venv\Scripts\python.exe test_interactive.py
```
* **Scenario 1:** Smart Thermostat Normal Heartbeat (Expected: `NORMAL`, score $\approx 0.0\%$)
* **Scenario 2:** DDoS SYN Flood Attack (Expected: `CRITICAL`, score $\approx 100.0\%$)
* **Scenario 3:** Mirai Botnet Telnet Scan (Expected: `CRITICAL`, score $\approx 100.0\%$)
* **Scenario 4:** Slow Port Sweep / Reconnaissance (Expected: `HIGH`, score $\approx 75-80\%$)
* **Option 5:** Run all scenarios consecutively.

---

### Method 2: Batch Inspection on Real & Unseen Traffic

**Inspect 50,000 Real Physical Testbed Records:**
```powershell
.\.venv\Scripts\python.exe main.py --detect --input "data/real_ciciot_dataset.csv"
```

**Inspect 500 Unseen Simulated Records:**
```powershell
.\.venv\Scripts\python.exe main.py --detect --input "data/demo_unseen_traffic.csv"
```
*(If no `--input` is provided, `main.py --detect` defaults to `data/demo_unseen_traffic.csv` for fast testing).*

---

### Method 3: Retrain the AI Model on Real Data
To train the Histogram Gradient Boosting model on the 50,000-record benchmark:

```powershell
.\.venv\Scripts\python.exe main.py --train --data "data/real_ciciot_dataset.csv" --model-type hist_gb
```

---

### Method 4: Automated 1-Click Demo
Generates synthetic data, trains a test model, and executes detection end-to-end:

```powershell
.\.venv\Scripts\python.exe main.py --demo
```

---

## 6. Programmatic Usage in Python Code

To inspect live network flows inside your own Python scripts or traffic listeners:

```python
from src.detect import IoTTrafficDetector

# 1. Load the trained AI model pipeline
detector = IoTTrafficDetector()

# 2. Define a real-time network flow sample
flow_sample = {
    "flow_duration": 0.001,       # Microsecond flood
    "Header_Length": 64,
    "Protocol Type": 6.0,         # TCP
    "Rate": 15000.0,              # Extreme packet rate
    "syn_flag_number": 1.0,
    "ack_flag_number": 0.0,
    "syn_count": 45,
    "ack_count": 0,
    "rst_count": 0,
    "HTTP": 0.0,
    "HTTPS": 0.0,
    "DNS": 0.0,
    "Telnet": 0.0,
    "SSH": 0.0,
}

# 3. Inspect the flow
result = detector.detect_single_flow(flow_sample)
print(result)
# Output: {'prediction': 'ABNORMAL', 'anomaly_score': 0.9984, 'risk_level': 'CRITICAL', 'is_threat': True}
```

---

## 7. Academic Performance Metrics (Holdout Evaluation)

Evaluated against 10,000 completely unseen holdout records from `real_ciciot_dataset.csv`:

* **Overall Accuracy:** $> 99.8\%$
* **Recall / Detection Rate:** $> 99.8\%$
* **False Alarm Rate (FPR):** $< 0.1\%$
* **Precision:** $> 99.9\%$
* **ROC-AUC Score:** $> 0.9998$
