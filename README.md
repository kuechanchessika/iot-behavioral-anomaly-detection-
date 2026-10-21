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

### Research & Implementation Progress

| Component / Milestone | Scope & Deliverable | Status |
| :--- | :--- | :---: |
| **Layer 1: Cryptographic Auth** | Ed25519 token signatures & X.509 device identity verification | *Planned* |
| **Layer 2: AI Anomaly Detection** | `HistGradientBoostingClassifier` on 46 flow features (CIC-IoT2023) | **Completed (99.99% Accuracy)** |
| **Full Benchmark Training** | Trained & validated on complete 50,000 real physical testbed flows | **Completed** |
| **Interactive Scenario Selector** | Colored interactive terminal menu for instant testing (SYN, Benign, Full 50k, Custom) | **Completed** |
| **ANSI Colorized Security CLI** | High-visibility terminal alert triage with NIST/CVSS severity colors | **Completed** |
| **Explainable AI (LLM Analyst)** | Multi-provider threat forensic reporting (OpenRouter, DeepSeek, OpenAI, Claude) | **Completed** |
| **NS-3 Physical IoT Testbed** | Real-time emulation bridge for live physical hardware validation | *Planned (Week 6)* |
| **Layer 3: Zero Trust Mitigation** | Cyber-physical safety rules & actuator fail-safe state gatekeeper | *Planned* |

---

## 2. Dataset Architecture: Real Physical Benchmark

The framework operates on physical IoT telemetry extracted from the University of New Brunswick **CIC-IoT2023** benchmark:

| Dataset File | Records | Normal Flows | Attack Flows | Source / Origin | Purpose |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **`real_ciciot_dataset.csv`** | **50,000** | 25,000 (50.0%) | 25,000 (50.0%) | **Physical Testbed:** Official UNB CIC-IoT2023 benchmark recorded from 105 real physical IoT devices. | **Primary Academic Benchmark:** Ground-truth training, cross-validation, and thesis performance evaluation. |

> **Note on Data Authenticity:** Synthetic demo files were removed to ensure 100% scientific validity and prevent accidental training on artificial random distributions. All training, validation, and detection operate exclusively on real physical IoT network traffic.

---

## 3. Repository Directory Structure

```
AI defense/
│
├── data/                                    # Real network traffic datasets
│   └── real_ciciot_dataset.csv              # 50,000 real physical testbed records (Benchmark)
│
├── models/                                  # Trained AI model weights & evaluation metadata
│   ├── iot_anomaly_detector.joblib          # Serialized pipeline (Scaler + Trained Model)
│   └── model_metadata.json                  # Performance metrics, feature schema & timestamp
│
├── logs/                                    # Automated forensic audit & alert quarantine records
│   ├── llm_reports/                         # LLM explainable AI threat reports (JSON + TXT)
│   ├── detection_log_*.csv                  # Full audit log of all inspected network flows
│   └── alerts_*.csv                         # Isolated threat alerts passed to Layer 3
│
├── src/                                     # Core engine source code
│   ├── config.py                            # Central paths, 46-feature schema, alert threshold
│   ├── preprocess.py                        # Imputation, label encoding, Z-score scaling
│   ├── train.py                             # HistGradientBoosting / Random Forest training pipeline
│   ├── detect.py                            # Real-time probability scoring, 4-tier triage & LLM trigger
│   ├── llm_analyst.py                       # Multi-provider LLM explainable AI threat analyst
│   ├── check_dataset.py                     # Dataset integrity verification utility
│   └── generate_sample_data.py              # Synthetic generator (kept for standalone utility)
│
├── test_interactive.py                      # Interactive attack scenario simulator CLI
├── main.py                                  # Unified Command-Line Interface (CLI)
├── real_data.py                             # Extractor script for 50,000 real CIC-IoT benchmark
├── AI_TRAINING_AND_DETECTION_REPORT.md      # Comprehensive research & technical report
├── .env.example                             # LLM API keys configuration template
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

### Method 2: Interactive Scenario Selection & Batch Inspection

Run automated threat detection with the interactive scenario selector:

```powershell
.\.venv\Scripts\python.exe main.py --detect
```

You will be presented with a colored interactive scenario menu:

```text
=======================================================
   IoT DEFENDER — SCENARIO SELECTION
=======================================================
  Which attack scenario do you want to test?

  1. SYN Flood Attack       (DDoS — real dataset)
  2. Normal Traffic Only    (benign flows only)
  3. Mixed — Full Dataset   (all 50,000 flows)
  4. Custom input file      (provide your own CSV)
=======================================================
  Enter choice (1-4):
```

* **Option 1 (SYN Flood Attack):** Automatically filters and evaluates the 25,000 DDoS-SYN Flood flows, isolating all threats and triggering LLM analysis.
* **Option 2 (Normal Traffic Only):** Evaluates 25,000 benign baseline flows with zero false alarms.
* **Option 3 (Mixed — Full Dataset):** Evaluates all 50,000 flows from the benchmark.
* **Option 4 (Custom file):** Provide any custom CSV path for real-time inspection.

To inspect a specific CSV file directly:
```powershell
.\.venv\Scripts\python.exe main.py --detect --input "data/real_ciciot_dataset.csv"
```

---

### Method 3: Retrain the AI Model on Real Data
To train the Histogram Gradient Boosting model on the 50,000-record benchmark:

```powershell
.\.venv\Scripts\python.exe main.py --train --data "data/real_ciciot_dataset.csv" --model-type hist_gb
```
*(If no `--data` is provided, `main.py --train` automatically defaults to `data/real_ciciot_dataset.csv`).*

---

### Method 4: Automated 1-Click Verification
Trains on a 10,000-flow sample of the real CIC-IoT dataset and executes threat detection end-to-end:

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

Trained and evaluated on **50,000 real flows** from the Canadian Institute for Cybersecurity (**CIC-IoT2023**) physical testbed (evaluated on 10,000 holdout records):

| Metric | Holdout Evaluation Result |
| :--- | :---: |
| **Accuracy** | **99.99%** |
| **Precision** | **100.00%** |
| **Recall / Detection Rate** | **99.98%** |
| **False Alarm Rate (FPR)** | **0.00%** |
| **ROC-AUC Score** | **1.0000** (0.999998) |
| **Inference Latency** | **< 0.1 ms / flow** |

* **Confusion Matrix (10,000 Holdout Flows):**
  * True Negatives (Normal flows correctly classified): **5,000 / 5,000**
  * False Positives (False alarms): **0**
  * False Negatives (Missed attacks): **1**
  * True Positives (Attacks detected): **4,999 / 5,000**

---

## 8. Explainable AI: LLM Threat Analyst Layer (`src/llm_analyst.py`)

Downstream from the Layer 2 ML anomaly scoring, top **CRITICAL** threats are automatically dispatched to a multi-provider LLM Threat Analyst to produce human-readable forensic reports.

### 8.1 Supported Providers
* **OpenRouter** (`deepseek/deepseek-chat`) — Default provider
* **DeepSeek Native** (`deepseek-chat`)
* **OpenAI** (`gpt-4o`)
* **Anthropic Claude** (`claude-3-5-sonnet-20241022`)

### 8.2 Configuration
Copy the provided template to configure API keys:
```powershell
Copy-Item .env.example .env
```
Set your active provider and key inside `.env`.

### 8.3 Sample Threat Report
```
=================================================================
  IoT Defender - LLM Threat Analysis Report
=================================================================
Timestamp    : 2026-10-19T14:05:19
Provider     : OPENROUTER (deepseek/deepseek-chat)
Source IP    : Flow-4
Severity     : CRITICAL
Threat Score : 1.0000
-----------------------------------------------------------------
1. ATTACK TYPE        : TCP SYN Flood (DDoS)
2. CONFIDENCE         : High
3. EXPLANATION        : SYN count 54,231 with zero ACKs confirms half-open
                        connection flood. Packet rate of 120K pps in 0.45s
                        indicates volumetric DDoS targeting IoT gateway.
4. IMPACT             : Gateway crash causing smart traffic/municipal failure.
5. RECOMMENDED ACTION : Block source IP immediately, rate-limit SYN packets.
=================================================================
```
All reports are automatically archived as structured **JSON** and human-readable **TXT** under `logs/llm_reports/`.

---

## 9. Academic References & Standards

1. **CIC-IoT2023 Benchmark:** Neto, E. C. P., et al. (2023). *CIC-IoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environments.* Sensors, 23(13), 5941.
2. **Network Simulation (NS-3):** Henderson, T. R., et al. (2008). *Network simulations with the ns-3 simulator.* ACM SIGCOMM.
3. **Incident Severity Standards:** Cichonski, P., et al. (2012). *Computer Security Incident Handling Guide.* NIST SP 800-61 Rev. 2.
4. **Explainable AI (XAI):** Gunning, D., et al. (2019). *XAI—Explainable Artificial Intelligence.* Science Robotics, 4(37).
5. **Mirai Attack Analysis:** Antonakakis, M., et al. (2017). *Understanding the Mirai Botnet.* 26th USENIX Security Symposium.
6. **Histogram Gradient Boosting:** Ke, G., et al. (2017). *LightGBM: A Highly Efficient Gradient Boosting Decision Tree.* NeurIPS 2017.
