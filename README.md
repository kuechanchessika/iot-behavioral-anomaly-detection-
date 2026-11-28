# Control 2: AI-Powered IoT Behavioral Anomaly Detection Engine

**Research Project:** A Cross-Protocol Anomaly Detection Framework for Connected IoT Infrastructure: Mitigating Cyber-Physical Attacks on Smart Traffic and Municipal Systems  
**Institution:** Concordia University  
**Component:** Control 2 / Layer 2 (AI-Powered Behavioral Anomaly Detection & State Engine)  
**Academic Benchmark:** Canadian Institute for Cybersecurity (**UNB CIC-IoT2023** Physical Testbed)  
**Status:** Renovated with Adaptive Windowing (ADWIN) & Parameterized Formulations (Week 8 & Week 9 Milestones)

---

## 1. Project Context & The Three-Layer Security Framework

This repository houses **Control 2 / Layer 2** of an integrated three-tier cybersecurity architecture designed to protect smart traffic intersections, SCADA telemetry, and connected municipal IoT infrastructure:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 1: Cryptographic Authentication                                      │
│ - Verifies device identity, certificates, and token signatures.             │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (Authenticated Network Traffic)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 2: AI-Based Behavioral Anomaly Detection (THIS MODULE)                 │
│ - Stage 1: Sticky Notes (is_inf_pkt_rate, is_nan_payload) + ADWIN Drift.    │
│ - Stage 2: Median Imputation without erasing heuristic flags.              │
│ - Stage 3: Robust MAD Scaling & Chebyshev Outlier Clipping (k ~ 31.62).     │
│ - Stage 4: HistGradientBoosting with Early Stopping & Latency Cap (<= 181). │
│ - Stage 5: Sigmoid Probability Scoring & Youden's J Calibration (tau*).     │
│ - Stage 6: Calibrated Risk Triage (Normal, Medium, High, Critical).         │
│ - Stage 7 & 8: LLM Threat Analyst Agent (DeepSeek-V3 Forensic Report).      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (Threat Alerts & Anomaly Scores)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 3: Zero Trust Cyber-Physical Safety Validation & Mitigation           │
│ - Dynamic connection dropping, compromised sensor quarantine.               │
│ - Actuator safe-state transition (e.g. flashing yellow traffic lights).     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Key Research Renovations (Week 8 & Week 9 Architecture Updates)

### 1. Replacing Static 5-Minute Window with Adaptive Windowing (ADWIN)
* **The Problem:** Fixed 300-second windows fail in IoT environments because devices transmit at heterogeneous rates (10–60 minutes), and stealth attackers can evade detection by sending one probe every 5 minutes.
* **The Solution:** ADWIN tracks **event streams** rather than elapsed wall-clock seconds. It retains normal baseline history as long as behavior stays stationary and cuts obsolete history only when distribution shift is mathematically confirmed ($D = |\mu_0 - \mu_1| > \varepsilon_{cut}$).
* **Verified Test Sequence:** On our project test stream $W = [1, 1, 1, 1, 6, 7, 3, 9, 1]$, ADWIN confirmed drift ($D = 4.2 > \varepsilon_{cut} = 1.485$), purged the old baseline, and emitted `adwin_port_drift = 4.2`.
* **Alarm Suppression:** Separates routine device reboots (completed TCP handshakes, normal flow duration $\implies$ alarm suppressed) from stealth port scans (unanswered handshakes, zero flow duration $\implies$ CRITICAL alert).

### 2. Systematic Removal of Magic Numbers (7 Pipeline Clusters)
All arbitrary constants have been replaced with statistically justified formulations:
1. **ADWIN Confidence ($\delta$):** Parameterized by operator SLA target false discovery rate: $\delta = \frac{\alpha_{target}}{N_{horizon}} = 1.0 \times 10^{-6}$.
2. **ADWIN Dispersion:** Empirical range $R_{dyn} = \max(W) - \min(W)$ with **Bernstein's Inequality** scaling by sample variance $\hat{\sigma}_W^2$ (maintained in $O(1)$ via Welford's algorithm).
3. **Sticky Note Boundaries:** Zero-duration boundary anchored to physical serialization delay: $\Delta t \le \varepsilon_t = 5.12\ \mu\text{s}$ ($\frac{512\text{ bits}}{10^8\text{ bps}}$ on 100 Mbps link); Zero-payload boundary anchored to protocol headers: $L_{payload} < L_{min\_app} = 2\text{ bytes}$ (MQTT fixed header).
4. **Robust Scaling & Chebyshev Clipping:** Robust Median Absolute Deviation (MAD) standardization ($z_{robust} = \frac{x - \text{med}}{\text{MAD} \times 1.4826}$) and Chebyshev outlier envelope $k_{clip} = \sqrt{\frac{1}{P_{tail\_allowance}}} \approx 31.62$.
5. **Ensemble Optimization:** Early stopping ($p = 10$, $\varepsilon_{loss} = 10^{-4}$) constrained by edge latency ceiling $T_{latency\_cap} = \lfloor \frac{\tau_{budget}}{t_{tree}} \rfloor = \lfloor \frac{1000\ \mu\text{s}}{5.5\ \mu\text{s}} \rfloor = 181$ trees.
6. **Decision Threshold Calibration:** $\tau^*$ dynamically derived via Youden's J Index ($\tau^* = \arg\max_\tau (\text{TPR} - \text{FPR})$) or Cost-Sensitive Bayes Risk.
7. **Capacity-Bounded LLM Triage:** $\tau_{critical} = \text{Quantile}_{1 - \beta}(P_{val})$ derived directly from hourly API token budget ($\beta = \frac{20}{10,000} = 0.002 \implies 99.8\text{th}$ percentile).

---

## 3. Repository Directory Structure

```
AI defense/
│
├── data/                                    # Real network traffic datasets
│   └── real_ciciot_dataset.csv              # Real UNB CIC-IoT physical testbed benchmark
│
├── models/                                  # Trained AI model weights & evaluation metadata
│   ├── iot_anomaly_detector.joblib          # Serialized pipeline (Scaler + Model + Calibration)
│   └── model_metadata.json                  # Performance metrics, feature schema & calibrated tau*
│
├── logs/                                    # Automated forensic audit & alert quarantine records
│   ├── llm_reports/                         # 5-Part LLM Threat Forensic Reports (JSON + TXT)
│   ├── detection_log_*.csv                  # Full audit log of all inspected network flows
│   └── alerts_*.csv                         # Isolated threat alerts passed to Layer 3
│
├── src/                                     # Core engine source code
│   ├── config.py                            # Central paths, schema, SLA-anchored parameters
│   ├── adwin.py                             # ADWIN Adaptive Windowing & Welford running variance
│   ├── preprocess.py                        # Sticky notes, median imputation, MAD robust scaling
│   ├── train.py                             # HistGradientBoosting with Early Stopping & Youden tau*
│   ├── detect.py                            # 8-stage inference, calibrated triage & LLM trigger
│   ├── llm_analyst.py                       # Stage 7 & 8 DeepSeek-V3 5-Part Forensic Threat Analyst
│   ├── test_benchmark.py                    # Multi-attack category benchmark evaluator
│   └── check_dataset.py                     # Dataset integrity verification utility
│
├── test_interactive.py                      # Interactive attack scenario simulator CLI
├── main.py                                  # Unified Command-Line Interface (CLI)
├── real_data.py                             # Multi-attack CIC-IoT benchmark dataset builder
├── AI_TRAINING_AND_DETECTION_REPORT.md      # Comprehensive research & mathematical report
├── .env.example                             # LLM API keys configuration template
├── requirements.txt                         # Python dependencies
└── README.md                                # Project documentation
```

---

## 4. How to Run and Test

Activate the project environment in PowerShell:

```powershell
cd "C:\Users\U-ser\OneDrive\Research Material Concordia\AI defense"
```

### Option 1: ADWIN Mathematical Proof (Week 8 & Week 9 Walkthrough)
Verify the exact 6-step mathematical calculation ($W_0, W_1, D = 4.2, \varepsilon_{cut} = 1.485$, and Bernstein bound):

```powershell
.\.venv\Scripts\python.exe main.py --adwin
```

### Option 2: Interactive Scenario Simulator CLI
Simulate realistic IoT operational and attack scenarios:

```powershell
.\.venv\Scripts\python.exe test_interactive.py
```
* **Scenario 1:** Smart Thermostat Normal Heartbeat (`NORMAL`, score $\approx 5.5\%$)
* **Scenario 2:** DDoS SYN Flood Attack (`CRITICAL`, $\Delta t \le 5.12\ \mu\text{s}$, score $= 100.0\%$)
* **Scenario 3:** Mirai Botnet Telnet Brute Force (`CRITICAL`, persistent port 23 probing)
* **Scenario 4:** Stealth Port Scan (`CRITICAL`, ADWIN drift $D = 4.2 > \varepsilon_{cut}$, incomplete handshakes)
* **Scenario 5:** Routine Device Reboot / Maintenance (`NORMAL`, brief port rise, valid handshakes, alarm suppressed)
* **Option 6:** ADWIN Mathematical Engine Walkthrough
* **Option 7:** Run all 5 scenarios consecutively.

### Option 3: Automated Batch Threat Detection
Inspect a network flow dataset CSV:

```powershell
.\.venv\Scripts\python.exe main.py --detect --input "data/real_ciciot_dataset.csv"
```
Or run the interactive scenario selector:
```powershell
.\.venv\Scripts\python.exe main.py --detect
```

### Option 4: Retrain Model with Dynamic Early Stopping & Youden Calibration
Train on real physical IoT telemetry with MAD robust scaling and edge latency capping:

```powershell
.\.venv\Scripts\python.exe main.py --train --data "data/real_ciciot_dataset.csv" --model-type hist_gb
```

---

## 5. Explainable AI: Stage 8 Five-Part Forensic Threat Report

When an anomaly score enters the capacity-bounded critical tier ($P \ge \tau_{critical}$), the alert payload is enriched with Stage 1 sticky notes and ADWIN port drift, then analyzed by the **DeepSeek-V3 LLM Threat Analyst Agent**:

```text
=================================================================
  IoT DEFENDER — LLM THREAT ANALYSIS FORENSIC REPORT
=================================================================
Provider     : DEEPSEEK-V3 (OpenRouter API)
Source IP    : 192.168.1.105
Severity     : CRITICAL
Threat Score : 1.0000

=== 5-PART FORENSIC THREAT REPORT ===
1. CLASSIFICATION       : Reconnaissance Port Scan / SYN Sweep
2. CONFIDENCE           : High (100.0% multi-stage correlation)
3. TECHNICAL ROOT-CAUSE : ADWIN confirmed port drift of +4.2 unique ports
                          exceeding cut hurdle of 1.485. Flow duration
                          <= 5.12 us serialization limit with zero ACKs.
4. OPERATIONAL IMPACT   : Mapping municipal controller open ports preceding
                          firmware exploitation or actuator sabotage.
5. RECOMMENDED ACTION   : Apply edge iptables drop rule, transition municipal
                          controller to hardware fail-safe (flashing yellow).
=================================================================
```

---

## 6. Academic References & Citations

1. **A. Bifet and R. Gavaldà**, "Learning from time-changing data with adaptive windowing," in *Proc. 7th SIAM Int. Conf. Data Mining (SDM)*, Minneapolis, MN, USA, 2007, pp. 443–448, doi: 10.1137/1.9781611972771.42.
2. **M. Datar, A. Gionis, P. Indyk, and R. Motwani**, "Maintaining stream statistics over sliding windows," *SIAM J. Comput.*, vol. 31, no. 6, pp. 1794–1813, 2002.
3. **T. Hastie, R. Tibshirani, and J. Friedman**, *The Elements of Statistical Learning: Data Mining, Inference, and Prediction*, 2nd ed. New York, NY, USA: Springer, 2009.
4. **J. H. Friedman**, "Greedy function approximation: A gradient boosting machine," *Ann. Statist.*, vol. 29, no. 5, pp. 1189–1232, 2001.
5. **E. C. P. Neto et al.**, "CIC-IoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environments," *Sensors*, vol. 23, no. 13, p. 5941, 2023.
