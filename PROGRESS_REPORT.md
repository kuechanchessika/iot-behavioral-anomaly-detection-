# Research Progress Report: Week 5
## Explainable AI (XAI) & Automated LLM-Driven Incident Response for Connected IoT Infrastructure

> **Project Title:** A Cross-Protocol Anomaly Detection Framework for Connected IoT Infrastructure: Mitigating Cyber-Physical Attacks on Smart Traffic and Municipal Systems  
> **Institution:** Concordia University  
> **Current Research Focus:** Integration of Multi-Provider LLM Threat Analyst, Automated Incident Triage, and Interactive Attack Scenario Selection Engine  
> **Date:** October 21, 2026  
> **Status:** Layer 2 Anomaly Detection & XAI Analyst Layer Completed  

---

## Executive Summary

In Week 4, we finalized the core Layer 2 behavioral anomaly detection pipeline using a Histogram-Based Gradient Boosting Classifier (`HistGradientBoostingClassifier`) evaluated on **50,000 real flows** from the UNB CIC-IoT2023 physical testbed (achieving **99.99% accuracy**, **100.00% precision**, **99.98% recall**, and **< 0.1 ms inference latency**). However, as noted in the Week 4 limitations, numeric anomaly probabilities and tabular flag metrics alone cannot inform non-expert municipal operators of the exact threat mechanism, cyber-physical consequences, or required emergency remediation.

During Week 5, we resolved this gap by designing, implementing, and experimentally validating an **Explainable AI (XAI) LLM Threat Analyst layer** immediately downstream of Layer 2:

1. **Multi-Provider LLM Forensic Engine (`src/llm_analyst.py`):** Integrated a unified threat translation pipeline supporting OpenRouter (DeepSeek-V3), DeepSeek Native, OpenAI (GPT-4o), and Anthropic (Claude 3.5 Sonnet).
2. **Automated Threat Triggering (`src/detect.py`):** Configured automated extraction and dispatch of top CRITICAL threats ($P(\text{Attack} \mid x) \ge 0.90$) directly into the LLM engine for sub-second plain-English forensic diagnosis.
3. **Structured Incident Archival (`logs/llm_reports/`):** Implemented dual forensic export producing structured JSON records alongside formatted text reports for municipal audit trails.
4. **Interactive Scenario Selection Engine (`main.py`):** Built a high-visibility ANSI-colorized operator interface supporting dynamic scenario filtering (SYN Flood DDoS, Benign Baseline, Full 50,000 Benchmark, Custom Captures).
5. **Credential Hardening & Codebase Synchronization:** Sanitized API key handling via `.env` isolation and synchronized the unified codebase across research repositories.

---

## Three-Layer Security Framework & Current Milestone Status

| Layer / Component | Research Role | Operational Question Answered | Implementation Status |
| :--- | :--- | :--- | :---: |
| **Layer 1** | Cryptographic Authentication & Identity Verification (TLS 1.3, X.509 PKI, Ed25519) | *Who is transmitting?* | Planned (Phase 3) |
| **Layer 2** | AI-Powered Behavioral Anomaly Detection (`HistGradientBoosting`, 46 features) | *How is the device behaving?* | **Completed & Evaluated (99.99% Acc)** |
| **LLM Analyst (XAI)** | Autonomous Forensic Threat Translation & Impact Analysis (DeepSeek / GPT-4o / Claude) | *What does this anomaly mean, and what is the physical impact?* | **Completed (Week 5 Focus)** |
| **Layer 3** | Zero Trust Cyber-Physical Safety Validation & Actuator Gatekeeper | *What safe-state action must municipal actuators take?* | Planned (Week 6–7) |

---

## 1. Background & Research Motivation: The Explainability Gap

In municipal Cyber-Physical Systems (CPS)—such as networked traffic light controllers, smart water grids, and roadside telemetry sensors—anomaly detection models must operate at line rate ($< 0.1\text{ ms}$ per flow). While tree-based ensembles (`hist_gb`) achieve superior throughput and near-zero false alarms, they output unadorned numeric tensors:

$$\mathbf{x} = [\text{Rate}=17000,\ \text{syn\_count}=85,\ \text{ack\_count}=0, \dots] \implies P(\text{Attack} \mid \mathbf{x}) = 0.9984 \implies \textbf{CRITICAL}$$

To a municipal traffic engineer or Security Operations Center (SOC) operator, this mathematical output leaves three critical operational questions unanswered:

1. **Semantic Ambiguity:** Which specific vulnerability or attack vector is exploiting the device (e.g., volumetric SYN flood vs. Mirai credential brute force)?
2. **Cyber-Physical Blast Radius:** Can this network anomaly cause physical cascading failures (e.g., controller lockup, green-green signal conflict, emergency vehicle preemption failure)?
3. **Actionable Remediation:** What precise network-level and physical-level commands must be executed immediately?

In Week 5, we solved this by deploying an autonomous LLM Threat Analyst layer that translates tabular network anomalies into concise, 5-part actionable intelligence reports.

---

## 2. Engineering Architecture: Multi-Provider LLM Threat Analyst

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          Layer 2 Detection & XAI Pipeline                               │
└────────────────────────────────────────────────────────────────────────────────────────┘
  Incoming Telemetry Flow (46 Features)
           │
           ▼
  [ Preprocessor & StandardScaler ] ───► Z-Score Normalized Feature Vector
           │
           ▼
  [ HistGradientBoosting Classifier ] ───► Anomaly Probability P(Attack | x)
           │
           ▼
  [ NIST SP 800-61 Triage Engine ]
     ├─ NORMAL   (0.00% – 49.99%)  ──► Permitted; background audit logged
     ├─ MEDIUM   (50.00% – 74.99%) ──► Warning flag; device monitoring increased
     ├─ HIGH     (75.00% – 89.99%) ──► Alert & rate-limiting watchlist
     └─ CRITICAL (90.00% – 100.0%) ──► Isolated to logs/alerts_*.csv
                                              │
                                              ▼
                    [ Top-3 CRITICAL Anomaly Extractor ]
                                              │
                                              ▼
                    [ LLM Threat Analyst (src/llm_analyst.py) ]
                       ├─ OpenRouter (DeepSeek-V3) [Default]
                       ├─ OpenAI (GPT-4o)
                       └─ Anthropic (Claude 3.5 Sonnet)
                                              │
                                              ▼
                    [ 5-Part Plain-Text Human Incident Report ]
                       ├─ Console: ANSI Colorized High-Visibility Output
                       └─ Storage: logs/llm_reports/ (Structured JSON + TXT)
```

### 2.1 Multi-Provider Architecture (`src/llm_analyst.py`)
The analyst module provides zero vendor lock-in via a unified REST client architecture supporting multiple leading foundation models:
* **OpenRouter (`deepseek/deepseek-chat`):** Serves as the primary production engine due to high reasoning efficiency, low operational inference costs, and exceptional domain knowledge in cybersecurity.
* **DeepSeek Native (`deepseek-chat`):** Direct API integration for dedicated regional deployments.
* **OpenAI (`gpt-4o`):** Enterprise fallback for high-concurrency environments.
* **Anthropic (`claude-3-5-sonnet-20241022`):** Advanced safety analysis and complex cyber-physical reasoning.

### 2.2 Prompt Engineering & Feature Grounding
To prevent LLM hallucination and ensure strict technical fidelity, the module injects exact numeric flow measurements directly into a structured prompt schema:
* **Injected Parameters:** Source IP, Destination IP, Transport Protocol, Calibrated Anomaly Score, NIST Severity Level, Cumulative SYN Count, ACK Count, RST Count, Flow Duration (seconds), Packet Rate (pps), and Encapsulated Services (HTTP, DNS, Telnet, SSH).
* **Strict Formatting Rules:** Explicit system constraints enforce clean, plain-text output without markdown artifacts, asterisks, or hash symbols, ensuring readability across standard terminal consoles.

### 2.3 Automated Forensic Archival
Every analysis automatically produces dual synchronized audit records under `logs/llm_reports/`:
* **Structured JSON (`llm_report_<timestamp>.json`):** Machine-readable telemetry snapshot, model identifier, execution latency, and raw prediction scores for SIEM/SOAR ingestion.
* **Human-Readable Text (`llm_report_<timestamp>.txt`):** Formatted executive forensic report ready for municipal safety compliance filings.

---

## 3. Interactive Attack Menu & Colored Terminal Output

To make testing easier without needing to remember long command-line flags, a simple interactive menu was added to main.py. This lets users pick which traffic scenario to test directly from the terminal.

### 3.1 Scenario Menu (python main.py --detect)

`	ext
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
`

* **Option 1 (SYN Flood Attack):** Tests 25,000 DDoS-SYN Flood flows from data/real_ciciot_dataset.csv to verify attack detection and trigger the LLM threat report.
* **Option 2 (Normal Traffic Only):** Tests 25,000 normal/benign flows to check that no false alarms are raised.
* **Option 3 (Mixed Benchmark):** Evaluates all 50,000 flows together.
* **Option 4 (Custom File):** Lets you load any custom CSV file to test new traffic captures.

### 3.2 Color-Coded Terminal Output
Added basic terminal color coding to src/detect.py and src/llm_analyst.py so results are easy to spot at a glance:
* CRITICAL -> **Red**
* HIGH -> **Yellow**
* MEDIUM -> **Cyan**
* NORMAL -> **Green**

---

## 4. Experimental Validation & LLM Output Case Studies

### 4.1 Case Study 1: Volumetric DDoS SYN Flood Detection & Report Generation
During execution of Scenario 1 (SYN Flood Attack), Layer 2 processed 25,000 attack flows in 2.6 seconds. The top anomalous flow exhibited the following header profile:
* **Protocol Type:** 6.0 (TCP)
* **Rate:** 120,450.0 packets/second
* **syn_count:** 54,231 packets
* **ack_count:** 0 packets
* **rst_count:** 14 packets
* **flow_duration:** 0.45 seconds
* **Layer 2 Output:** $P(\text{Attack} \mid \mathbf{x}) = 1.0000 \implies \textbf{CRITICAL}$

#### LLM Threat Analyst Generated Report
```text
=================================================================
     LLM THREAT ANALYST REPORT -- IoT Defender
=================================================================
  Timestamp    : 2026-10-20T17:16:15
  Provider     : OPENROUTER (deepseek/deepseek-chat)
  Source IP    : Flow-4
  Severity     : CRITICAL
  Threat Score : 1.0000
-----------------------------------------------------------------
ANALYSIS:

1. ATTACK TYPE        : TCP SYN Flood Attack (Volumetric DDoS)
2. CONFIDENCE         : High
3. EXPLANATION        : The flow records an extreme packet transmission rate of 
                        120,450 pps with 54,231 SYN packets and zero ACKs over 
                        just 0.45 seconds. This total absence of acknowledgments 
                        demonstrates intentional half-open TCP state exhaustion.
4. IMPACT             : Severe danger to municipal IoT gateways. Saturated TCP 
                        connection tables will trigger gateway denial-of-service, 
                        cutting off communications to connected smart traffic 
                        controllers and vehicle safety telemetry.
5. RECOMMENDED ACTION : 1. Instantly drop and blacklist Source IP at edge firewall.
                        2. Enable SYN cookies on the municipal IoT gateway.
                        3. Restrict TCP SYN rates to 10,000 pps per ingress interface.
                        4. Dispatch safe-state standby signal to Layer 3 actuators.
=================================================================
```

### 4.2 Case Study 2: Normal Sensor Telemetry Validation
During execution of Scenario 2 (Normal Traffic Only), 25,000 benign records were evaluated:
* **syn_count:** 1
* **ack_count:** 8
* **rst_count:** 0
* **Rate:** 4.5 packets/second
* **HTTP:** 1.0, **DNS:** 1.0
* **Layer 2 Output:** $P(\text{Attack} \mid \mathbf{x}) = 0.0000 \implies \textbf{NORMAL (Allowed)}$
* **Outcome:** Exactly 0 false alarms raised across 25,000 flows (0.00% FPR). No spurious LLM API calls triggered.

---

## 5. Answers to Core Research Questions (Updated for Week 5)

* **RQ2: Can AI accurately identify abnormal behavior and malicious traffic from IoT devices at line rate?**  
  *Week 5 Finding:* **Confirmed.** The Histogram-Based Gradient Boosting Classifier processes flows at $< 0.1\text{ ms}$ per flow with **99.99% accuracy** on the full 50,000-flow benchmark.
* **RQ3: Can AI detect malicious behavior from legitimate but compromised IoT devices?**  
  *Week 5 Finding:* **Confirmed.** When a legitimate IoT device is hijacked (evaluated using the Mirai Botnet Telnet credential brute-force test scenario on Port 23), behavioral feature modeling detects the anomaly with an **84.00% threat probability score (HIGH Severity)** and triggers immediate containment ([!] Security Action: ISOLATED & ALERT TRIGGERED). This empirically validates that Layer 2 behavioral AI overcomes the blind spot of Layer 1 cryptographic authentication, which cannot detect malicious commands issued by validly credentialed nodes.
* **RQ4 (New): Can Explainable AI (XAI) bridge the semantic gap between numeric ML outputs and municipal cyber-physical safety enforcement?**  
  *Week 5 Finding:* **Yes.** By pairing low-latency tabular boosting with multi-provider LLM prompt reasoning, the system successfully extracts physical failure semantics and actionable firewall/actuator commands from pure packet metrics without degrading detection throughput.

---

## 6. Current Limitations & Challenges

1. **API Latency of LLM Reasoning:** While Layer 2 anomaly classification executes in $< 0.1\text{ ms}$, external cloud LLM API calls require 1.0–2.5 seconds to return. While acceptable for human incident review, emergency mitigation commands to Layer 3 actuators must not wait for the LLM output; Layer 3 must trigger automated safe-state rules based directly on numeric risk scores ($P \ge 0.90$).
2. **Attack Vector Diversity:** The benchmark model currently focuses on high-rate DDoS-SYN Floods and benign baseline flows. Multi-class expansion across other attacks in CIC-IoT2023 (ARP Spoofing, Mirai, Slowloris, UDP Floods) is needed.
3. **Local/Edge LLM Execution:** Reliance on cloud APIs (OpenRouter, OpenAI) requires internet connectivity. Deploying a quantized lightweight local model (e.g. LLaMA-3.2-3B-Instruct or DeepSeek-R1-Distill-1.5B via Ollama) on the edge gateway will be explored.

---

## 7. Next Phase Implementation Plan: Week 6 Roadmap

### Transition from Localhost Simulation to Real Physical IoT Testbed via NS-3

* **Research Motivation & Context:**  
  All testing conducted up to Week 5 was executed **locally on a single host computer**, relying on pre-recorded benchmark CSV files (
eal_ciciot_dataset.csv) and in-memory software simulators (	est_interactive.py). While this confirmed theoretical ML accuracy (99.99%), offline local testing cannot account for live hardware constraints, physical transmission latency, dynamic packet jitter, or real-time socket ingestion. To evaluate true operational accuracy and robustness, the framework must transition to live physical IoT hardware.

* **Specific Week 6 Milestones:**
  1. **NS-3 Real-Time Network Bridge Deployment:**  
     Configure **Network Simulator 3 (NS-3)** in real-time emulation mode (using TapBridge / raw network sockets) to serve as the communication fabric linking physical IoT devices to the AI defense engine.
  2. **Physical IoT Hardware Interfacing:**  
     Deploy and connect real physical IoT devices (e.g., Raspberry Pi nodes, edge microcontrollers, and physical sensor telemetry transmitters) to generate and transmit live network traffic into the NS-3 simulated municipal topology.
  3. **Live Socket Stream Ingestion & Line-Rate Scoring:**  
     Implement a live packet capture and feature extraction pipeline to ingest network flows from physical hardware in real time and feed them directly into the Layer 2 AI classifier.
  4. **Empirical Validation of Physical vs. Local Accuracy:**  
     Benchmark real-world detection accuracy, false positive rates, and line-rate inference throughput under physical network conditions (packet drops, jitter, transmission delay) to validate system performance beyond the local PC environment.

---

## Appendix: Repository Structure (Week 5)

```text
AI defense / IoT-Defender
├── data/
│   └── real_ciciot_dataset.csv              # 50,000 real physical testbed records (Benchmark)
├── models/
│   ├── iot_anomaly_detector.joblib          # Trained pipeline artifact (Scaler + Model)
│   └── model_metadata.json                  # Performance metrics, 46-feature schema & audit scores
├── logs/
│   ├── llm_reports/                         # Explainable AI incident reports (JSON + TXT)
│   ├── detection_log_*.csv                  # Complete forensic flow inspection logs
│   └── alerts_*.csv                         # Isolated threat quarantine logs consumed by Layer 3
├── src/
│   ├── config.py                            # 46-feature schema, file paths, alert thresholds
│   ├── preprocess.py                        # Zero-leakage median imputation, Z-score scaling
│   ├── train.py                             # HistGradientBoosting / Random Forest trainer
│   ├── detect.py                            # Line-rate probability scorer & LLM auto-trigger
│   ├── llm_analyst.py                       # Multi-provider LLM explainable AI analyst (XAI)
│   ├── check_dataset.py                     # Dataset integrity verification utility
│   └── generate_sample_data.py              # Standalone synthetic generator
├── main.py                                  # CLI with colored interactive scenario selector
├── test_interactive.py                      # Scenario simulator (Thermostat, SYN Flood, Mirai, PortScan)
├── real_data.py                             # Benchmark data partition utility
├── .env.example                             # Sanitized API configuration template
├── requirements.txt                         # Python dependencies (requests, dotenv, scikit-learn)
└── README.md                                # Comprehensive project documentation & progress tracker
```
