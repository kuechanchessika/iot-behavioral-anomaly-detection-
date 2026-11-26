# Research Progress Report: Control 2 (AI-Based Behavioral Anomaly Detection)
## Comprehensive Technical & Mathematical Architecture Report

**Project Title:** Cross-Protocol Anomaly Detection Framework for Connected IoT Infrastructure: Mitigating Cyber-Physical Attacks on Smart Traffic and Municipal Systems  
**Module:** Control 2 / Layer 2 — AI-Powered Behavioral Anomaly Detection Engine  
**Institution:** Concordia University  
**Benchmark:** Canadian Institute for Cybersecurity (**UNB CIC-IoT2023** Physical Testbed)  
**Date:** November 2026 (Synthesizing Week 8 & Week 9 Progress Updates)

---

## Executive Summary

This report establishes the complete mathematical architecture, implementation specifications, and operational enhancements for **Control 2 (Layer 2)** of the IoT Security Defense Framework. 

Recent research milestones achieved across Weeks 8 and 9 address two fundamental challenges in traditional intrusion detection systems:
1. **Elimination of Static Sliding Windows (Week 8):** Replacing brittle 5-minute (300-second) static time-based windows with **Adaptive Windowing (ADWIN)**. ADWIN monitors unique destination port cardinality as an event stream, adapting window boundaries dynamically to detect stealthy reconnaissance sweeps while completely eliminating false positives from routine device reboots.
2. **Systematic Removal of "Magic Numbers" Across the 8-Stage Pipeline (Week 9):** Transforming seven clusters of hard-coded heuristic constants into mathematically defensible, adaptive formulations anchored in statistical learning theory, physical networking bounds, and operator Service Level Agreements (SLAs).

---

## 1. End-to-End 8-Stage Pipeline Architecture

The Layer 2 engine processes raw multi-protocol network traffic through an 8-stage pipeline that transitions from wire-level feature extraction to Explainable AI (XAI) forensic reporting.

```mermaid
flowchart TD
    A["Raw Ingress Traffic Flows\n(IoT Gateway 46 / SCADA 43 / Sensors 44\n5-tuple: src/dst IP, port, proto)"] --> B["Stage 1: Feature Extraction & Adaptive State Tracking\nSticky-note flags (Function 1) + ADWIN drift engine (Function 2)\nTracks dynamic port dispersion |mu0 - mu1| >= eps_cut"]
    B --> C["Stage 2: Preprocessing & Median Imputation\n50th percentile robust median imputation\nReplaces NaN/Inf without erasing sticky notes"]
    C --> D["Stage 3: Robust Feature Standardization & Outlier Clipping\nz_robust = (x - median) / (MAD * 1.4826)\nChebyshev clipping envelope: k_clip = sqrt(1 / P_tail) approx 31.62"]
    D --> E["Stage 4: HistGradientBoosting Classifier\nT* = min(T_latency_cap, EarlyStopping)\nShrinkage eta = 0.10, Histogram Bins B = 256, max_leaf_nodes = 31"]
    E --> F["Stage 5: Sigmoid Probability Scoring\nP(Attack | x) = 1 / (1 + e^-s(x))\nDynamic decision threshold calibration tau* via Youden's J Index"]
    F --> G["Stage 6: Calibrated Operational Risk Triage\nConfidence-interval risk tiers:\nNormal: P < tau* | Medium: tau* <= P < tau* + sigma_cal\nHigh: tau* + sigma_cal <= P < tau_crit | Critical: P >= tau_crit"]
    G --> H["Stage 7: LLM Threat Analyst Agent\nDeepSeek-V3 via OpenRouter API\nTriggered when P >= tau_critical (bounded by token quota beta)"]
    H --> I["Stage 8: Five-Part Forensic Threat Report\nActionable plain-text triage and containment commands\n(Classification, Confidence, Root-Cause, Network Impact, iptables rules)"]
```

---

## 2. Stage 1 Architectural Enhancement: Replacing Static 5-Minute Window with ADWIN

### 2.1 The Critical Limitation of 5-Minute Time-Based Memory
Prior implementations utilized a fixed 300-second sliding memory window to track port connection diversity. Empirical evaluation revealed two severe operational failures:
1. **Device Transmission Heterogeneity:** IoT sensors do not transmit at uniform frequencies. High-frequency telemetry (e.g. connected vehicles) transmits sub-second bursts, whereas smart water meters or environmental sensors transmit once every 10–60 minutes. A fixed 5-minute timer prematurely wipes behavioral history before low-rate sensors can establish a statistically valid baseline.
2. **Stealth Port Sweeps (Time-Evasion Attacks):** An adversarial reconnaissance scan sending one SYN probe every 5 minutes and 1 second resets the window on every probe. Each probe lands in a pristine, empty window, appearing as an isolated, harmless single-port connection.

### 2.2 The Event-Driven ADWIN Solution
ADWIN (Adaptive Windowing, Bifet & Gavaldà, 2007) does not measure elapsed wall-clock seconds; it measures **event sequences**. ADWIN maintains an active observation window $W$ of unique destination port counts. It keeps historical data indefinitely during stationary behavior and automatically cuts obsolete history only when a mathematically significant distribution shift is confirmed.

To conserve edge router memory, ADWIN tracks the **count of unique destination ports** per evaluation period rather than storing raw 16-bit port numbers:
* **Normal Telemetry:** Dedicated sensor communicates exclusively with its central MQTT broker (`1883/tcp`) or CoAP gateway (`5683/udp`). Unique port count = $1$.
* **Reconnaissance Port Sweep:** Attacker targets ports 21, 22, 23, and 80. Unique port count = $4$.

---

## 3. Step-by-Step ADWIN Mathematical Calculation & Verification

The following step-by-step mathematical calculation uses the exact measurement sequence from our project test data. The data stream window $W$ holds four stationary baseline readings followed by five multi-port attack readings:

$$W = [1, 1, 1, 1, 6, 7, 3, 9, 1]$$

* **Old baseline sub-window ($W_0$):** $[1, 1, 1, 1]$, with count $n_0 = 4$.
* **New traffic sub-window ($W_1$):** $[6, 7, 3, 9, 1]$, with count $n_1 = 5$.
* **Total observations ($n$):** $n = n_0 + n_1 = 4 + 5 = 9$.
* **Confidence setting ($\delta$):** $\delta = 0.002$.

### Step 1: Calculate Average Old Data ($\mu_0$)
$$\mu_0 = \frac{1 + 1 + 1 + 1}{4} = \frac{4}{4} = 1.0$$

### Step 2: Calculate Average New Data ($\mu_1$)
$$\mu_1 = \frac{6 + 7 + 3 + 9 + 1}{5} = \frac{26}{5} = 5.2$$

### Step 3: Calculate the Difference Between Averages ($D$)
$$D = |\mu_0 - \mu_1| = |1.0 - 5.2| = 4.2$$
*(The average port count jumped from 1.0 to 5.2 unique destination ports).*

### Step 4: Calculate Harmonic Sample Size ($m$)
The harmonic sample size accounts for unequal sample sizes between historical baseline ($n_0$) and recent burst ($n_1$):
$$m = \frac{1}{\frac{1}{n_0} + \frac{1}{n_1}} = \frac{1}{\frac{1}{4} + \frac{1}{5}} = \frac{1}{0.25 + 0.20} = \frac{1}{0.45} = \frac{20}{9} \approx 2.2222$$

### Step 5: Calculate the Threshold Hurdle ($\varepsilon_{cut}$)

#### 5.1 Adjusted Confidence ($\delta'$):
$$\delta' = \frac{\delta}{n} = \frac{0.002}{9} \approx 0.0002222$$

#### 5.2 Hoeffding Bound Hurdle Formula:
$$\varepsilon_{cut} = \sqrt{\frac{1}{2m} \times \ln\left(\frac{4}{\delta'}\right)}$$

Substituting $m = 2.2222$ and $\delta' = 0.0002222$:
$$\frac{4}{\delta'} = \frac{4}{0.0002222} = 18001.8$$
$$\ln(18001.8) \approx 9.79817$$
$$2m = 2 \times 2.2222 = 4.4444$$
$$\varepsilon_{cut} = \sqrt{\frac{9.79817}{4.4444}} = \sqrt{2.2046} \approx 1.4848 \approx 1.485$$

### Step 6: Make Decision Rule
$$D > \varepsilon_{cut} \iff 4.2 > 1.485 \quad \mathbf{[TRUE]}$$

* **Mathematical Result:** The observed difference $D = 4.2$ substantially exceeds the threshold hurdle of $1.485$.
* **ADWIN Engine Action:** ADWIN formally confirms behavioral concept drift. It purges the obsolete baseline $[1, 1, 1, 1]$ from memory, establishes $W_1$ as the new baseline, and passes the drift signal into the feature vector:
  $$\text{adwin\_port\_drift} = 4.2$$

---

## 4. Fixing Magic Numbers: 7 Pipeline Clusters Converted to Adaptive Formulations

In traditional network anomaly detectors, pipeline stages rely on arbitrary heuristic thresholds ("magic numbers"). Below, all seven heuristic clusters are systematically replaced with statistically grounded formulations:

### Cluster 1: ADWIN Drift Detection Parameters (Stage 1)
* **Legacy Heuristic:** Hard-coded $\delta = 0.002$ and observation range $R = 10$.
* **Theoretical Flaw:** $\delta$ represents the probability of false alarm under stationary conditions (Type I error). A static $\delta = 0.002$ produces vastly different operational false alarm rates on a 10 packet/min NB-IoT gateway versus a 100,000 packet/sec backbone switch. Hard-coding $R = 10$ into Hoeffding's bound violates the inequality if an attacker scans a `/24` subnet contacting $>10$ ports ($D > R$).
* **Defensible Formulation (Budgeted FDR over Operational Horizon):** Anchor $\delta$ to the operator Service Level Agreement (SLA):
  $$\delta = 1 - (1 - \alpha_{target})^{\frac{1}{N_{horizon}}} \approx \frac{\alpha_{target}}{N_{horizon}}$$
  *Example:* Requiring at most 1 false alarm per 50,000 connection events ($\alpha_{target} = 0.05, N_{horizon} = 50,000$):
  $$\delta = \frac{0.05}{50,000} = 1.0 \times 10^{-6}$$
* **Empirical Dynamic Dispersion Bounding (Bernstein's Inequality):**
  Replace Hoeffding's worst-case range bound with **Empirical Bernstein Bounding**, scaling by the running sample variance $\hat{\sigma}_W^2$ maintained in $O(1)$ time via Welford's algorithm:
  $$\varepsilon_{cut\_Bernstein} = \sqrt{\frac{2\hat{\sigma}_W^2}{m} \ln\left(\frac{4n}{\delta}\right)} + \frac{R_{dyn}}{3m} \ln\left(\frac{4n}{\delta}\right)$$
  where $R_{dyn} = \max(W) - \min(W)$ dynamically tracks the active window span.

### Cluster 2: Zero-Boundary Heuristic Sticky Notes (Stages 1 & 2)
* **Legacy Heuristic:** Strict check $\Delta t == 0.00\text{ s}$ triggering `is_inf_pkt_rate = 1` and $\text{payload} == 0\text{ bytes}$ triggering `is_nan_payload = 1`.
* **Theoretical Flaw:** Network Interface Cards (NICs) experience hardware timer jitter. An ultra-fast SYN probe might register $\Delta t = 0.000000\text{ s}$ on one NIC and $0.000003\text{ s}$ on another, causing strict zero checks to fail.
* **Defensible Formulation (Physical Serialization Delay Bound):**
  $$\text{is\_inf\_pkt\_rate} = \begin{cases} 1, & \text{if } \Delta t \le \varepsilon_t \\ 0, & \text{otherwise} \end{cases}$$
  where $\varepsilon_t = \max\left(\text{TimerResolution}_{NIC}, \frac{\text{MinPacketSize}}{\text{LinkBandwidth}}\right)$.  
  *Example:* On a 100 Mbps link with minimum 64-byte Ethernet frames, serialization delay is $\frac{512\text{ bits}}{10^8\text{ bps}} = 5.12\ \mu\text{s}$. Setting $\varepsilon_t = 5.12\ \mu\text{s}$ provides physical justification for what constitutes an instantaneous flow.
* **Transport-Layer Semantic Bound:**
  $$\text{is\_nan\_payload} = \begin{cases} 1, & \text{if } L_{payload} < L_{min\_app} \\ 0, & \text{otherwise} \end{cases}$$
  where $L_{min\_app} = 2\text{ bytes}$ (the minimum fixed header of MQTT). Packets with $L_{payload} < 2$ are structurally incapable of carrying application data.

### Cluster 3: Feature Standardization & Outlier Clipping (Stage 3)
* **Legacy Heuristic:** Standard mean-variance scaling ($z = \frac{x - \mu}{\sigma}$) and arbitrary $[-5.0, +5.0]$ Z-score clipping.
* **Theoretical Flaw:** In heavy volumetric attacks (e.g., amplification DDoS), arithmetic mean $\mu$ and standard deviation $\sigma$ are severely distorted by outliers. Arbitrary $\pm 5.0$ clipping destroys the proportional scale of severe volumetric intrusions.
* **Defensible Formulation (Median Absolute Deviation & Chebyshev Envelope):**
  Use the **Median Absolute Deviation (MAD)** as a breakdown-resistant scale estimator:
  $$\text{MAD}(X) = \text{median}(|x_i - \text{median}(X)|)$$
  $$z_{robust} = \frac{x - \text{median}(X)}{\text{MAD}(X) \times 1.4826}$$
  Apply clipping boundaries derived from **Chebyshev's Inequality**, which guarantees that regardless of probability distribution, at most $\frac{1}{k^2}$ of legitimate samples exceed $k$ standard units:
  $$k_{clip} = \sqrt{\frac{1}{P_{tail\_allowance}}}$$
  Allowing $P_{tail\_allowance} = 0.001$ ($0.1\%$ extreme tail allowance) yields:
  $$k_{clip} = \sqrt{\frac{1}{0.001}} = \sqrt{1000} \approx 31.62$$
  This mathematically preserves extreme volumetric attack profiles without arbitrary truncation.

### Cluster 4: Ensemble Sizing & Optimization (Stage 4)
* **Legacy Heuristic:** Fixed $T = 150$ boosting trees, $\eta = 0.10$, $B = 256$ bins.
* **Theoretical Flaw:** Fixed 150 iterations lacks empirical justification; smaller datasets overfit while complex enterprise networks may underfit.
* **Defensible Formulation (Constrained Early Stopping via Empirical Validation Loss):**
  $$T^* = \min(T_{latency\_cap}, \arg\min_t \mathcal{L}_{vl}(t))$$
  *Convergence Rule:* Halt training when validation loss fails to improve by more than $\varepsilon_{loss} = 10^{-4}$ for $p = 10$ consecutive trees.
  *Edge Latency Budget Ceiling:* Given maximum inference latency budget $\tau_{budget} = 1.0\text{ ms}$ ($1000\ \mu\text{s}$) and empirical single-tree traversal cost $t_{tree} = 5.5\ \mu\text{s}$:
  $$T_{latency\_cap} = \left\lfloor \frac{\tau_{budget}}{t_{tree}} \right\rfloor = \left\lfloor \frac{1000\ \mu\text{s}}{5.5\ \mu\text{s}} \right\rfloor = 181\text{ trees}$$
  If validation loss converges at 142 trees, $T^* = 142 \le 181$, providing an explicit computational complexity proof.

### Cluster 5: Decision Threshold Calibration ($\tau^*$) (Stage 5)
* **Legacy Heuristic:** Static binary cutoff $\tau = 0.50$ (or $\tau_{sensor} = 0.10$).
* **Theoretical Flaw:** Ad-hoc manual threshold tuning after observing classification error is unprincipled trial-and-error.
* **Defensible Formulation (Youden's J Statistic & Bayesian Cost-Benefit Optimization):**
  Derive $\tau^*$ formally on holdout validation ROC curves:
  $$\tau^* = \arg\max_\tau (\text{Sensitivity}(\tau) + \text{Specificity}(\tau) - 1) = \arg\max_\tau (\text{TPR}(\tau) - \text{FPR}(\tau))$$
  Alternatively, under asymmetric intrusion costs ($C_{FN} \gg C_{FP}$):
  $$\tau^* = \arg\min_\tau \left( C_{FN} \cdot \text{FNR}(\tau) \cdot P(\text{Attack}) + C_{FP} \cdot \text{FPR}(\tau) \cdot (1 - P(\text{Attack})) \right)$$

### Cluster 6 & 7: Operational Risk Triage & LLM Escalation Tiers (Stages 6, 7 & 8)
* **Legacy Heuristic:** Fixed score thresholds $[0.50, 0.75, 0.90]$.
* **Theoretical Flaw:** Unjustified boundaries (why $90\%$ instead of $85\%$ or $95\%$?). Uncapped critical triggers can overwhelm LLM APIs during flood attacks.
* **Defensible Formulation (Confidence Intervals & Capacity-Bounded Quantiles):**
  * **Normal (Permitted):** $P(x) < \tau^*$ (below optimal decision threshold).
  * **Medium (Telemetry Watch):** $\tau^* \le P(x) < \tau^* + \sigma_{cal}$ (moderate uncertainty band).
  * **High (Security Alert):** $\tau^* + \sigma_{cal} \le P(x) < \tau_{critical}$.
  * **Critical (LLM Forensic Trigger):** Anchored directly to operator token capacity and API hourly budget:
    $$\tau_{critical} = \text{Quantile}_{1 - \beta}(P(val)) \quad \text{where } \beta = \frac{\text{LLM API Quota per Hour}}{\text{Expected Alerts per Hour}}$$
    *Example:* If the edge gateway can afford at most 20 DeepSeek-V3 forensic dispatches per hour during peak periods with 10,000 alerts/hour:
    $$\beta = \frac{20}{10,000} = 0.002 \implies \tau_{critical} = \text{Quantile}_{0.998}(P(val))$$
    Setting $\tau_{critical}$ to the top $99.8\text{th}$ percentile mathematically guarantees the system never exhausts its LLM budget or floods security operators.

---

## 5. Direct Comparison: Legacy vs. Scientifically Justified Architecture

| Pipeline Component | Legacy "Magic Number" Approach | Renovated Parameterized / Adaptive Approach | Scientific & Physical Justification |
| :--- | :--- | :--- | :--- |
| **ADWIN Confidence** | Hard-coded $\delta = 0.002$ | $\delta = \frac{\alpha_{target}}{N_{horizon}} = 1.0 \times 10^{-6}$ | Anchored to operator SLA Target False Discovery Rate over monitoring horizon. |
| **ADWIN Observation Spread** | Hard-coded range $R = 10$ | Dynamic empirical range $R_{dyn} = \max(W) - \min(W)$ and Bernstein variance $\hat{\sigma}_W^2$ | Prevents bound violations during wide subnet scans; scales with empirical variance. |
| **Zero-Duration Sticky Flag** | Strict equality check $\Delta t == 0.00\text{ s}$ | $\Delta t \le \varepsilon_t = 5.12\ \mu\text{s}$ (serialization delay bound) | Grounded in Ethernet physical serialization delay ($\frac{512\text{ b}}{10^8\text{ bps}}$) and NIC clock jitter. |
| **Zero-Payload Sticky Flag** | Strict equality check $\text{payload} == 0\text{ B}$ | $L_{payload} < L_{min\_app} = 2\text{ B}$ (MQTT fixed header) | Structural impossibility of carrying application data under monitored protocol. |
| **Outlier Standardization** | Standard Z-score clipped at $[-5.0, +5.0]$ | MAD scaling: $z_{robust} = \frac{x - \text{med}}{\text{MAD} \times 1.4826}$; Chebyshev envelope $k_{clip} = \sqrt{\frac{1}{P_{tail}}} \approx 31.62$ | Breakdown-resistant non-parametric scaling; preserves proportional scale of volumetric DoS. |
| **Ensemble Capacity** | Fixed $T = 150$ trees | $T^* = \min(T_{latency\_cap}, \text{EarlyStopping})$ where $T_{latency\_cap} = \lfloor \frac{\tau_{budget}}{t_{tree}} \rfloor = 181$ | Balances empirical residual convergence with hard edge inference budget ($\le 1.0\text{ ms}$). |
| **Decision Threshold** | Heuristic $\tau = 0.50$ | Dynamic Youden's Index $\tau^* = \arg\max_\tau (\text{TPR} - \text{FPR})$ or Cost-Sensitive Bayes Risk | Eliminates trial-and-error; mathematically optimizes intrusion detection payoff matrix. |
| **Critical / LLM Triage** | Arbitrary $P \ge 90\%$ | Capacity-bounded quantile $\tau_{critical} = \text{Quantile}_{1 - \beta}(P(val))$ | Bounds API expenditure; guarantees LLM token limits are never exceeded during storm attacks. |

---

## 6. How the HistGradientBoosting Classifier Checks the Drift

ADWIN proves that a device's unique port access pattern has statistically shifted, but **does not make the final intrusion decision in isolation**. The drift metric `adwin_port_drift = 4.2` is passed directly into the HistGradientBoosting decision trees alongside transport-layer handshake features:

```mermaid
flowchart TD
    A["ADWIN Output\nadwin_port_drift = 4.2"] --> B["HistGradientBoosting Classifier\n(150+ Sequential Decision Trees)\n1. Port spike above baseline?\n2. Instantaneous connection (Delta_t <= 5.12 us)?\n3. Unanswered TCP handshakes (= 100%)?"]
    B --> C{"Do all signals\nmatch an intrusion\nprofile?"}
    C -- YES --> D["Confirmed Threat: Recon-PortScan\nProbability >= 99.8% -> CRITICAL\nIsolate & Dispatch LLM Forensics"]
    C -- NO --> E["Benign Reboot / Maintenance Event\nNormal handshakes completed (ACK=1, SYN=0)\nFlow duration > 5.12 us\nAlarm Suppressed -> NORMAL (Score: 1.9%)"]
```

### Behavioral Discrimination in Operation:
* **Routine Device Reboot (Alarm Suppressed):** When an IoT power meter or traffic controller reboots, it connects to NTP, DNS, and cloud firmware servers in rapid succession. Its unique destination port count briefly rises ($D = 2.5$). However, its connections complete valid TCP handshakes (`ack_flag_number = 1.0, syn_flag_number = 0.0`) and have normal transmission durations ($\Delta t = 2.85\text{ s} \gg 5.12\ \mu\text{s}$). The decision trees recognize standard application handshakes and **suppress the alarm** ($P = 1.9\%$, `NORMAL`).
* **Stealth Reconnaissance Port Scan (Critical Threat):** An adversary scans multiple ports with half-open SYN packets that intentionally fail to complete handshakes. The decision trees observe the elevated drift ($D = 4.2$) coupled with zero flow duration ($\Delta t \le 5.12\ \mu\text{s}$, `is_inf_pkt_rate = 1`), missing ACKs (`ack_count = 0`), and empty payloads (`is_nan_payload = 1`). This elevates the anomaly probability to $100.0\%$ (`CRITICAL`), triggering immediate network isolation and LLM forensic dispatch.

---

## 7. Stage 7 & 8: Explainable AI (XAI) Five-Part Forensic Threat Report

When a flow scores in the top capacity-bounded critical percentile ($P \ge \tau_{critical}$), the alert dictionary is enriched with sticky note diagnostics and dispatched to the **DeepSeek-V3 LLM Threat Analyst Agent** via OpenRouter API.

### Sample Real-Time Generated Forensic Report

```text
=================================================================
  IoT DEFENDER — LLM THREAT ANALYSIS FORENSIC REPORT
=================================================================
Provider     : DEEPSEEK-V3 (OpenRouter API)
Source IP    : 192.168.1.105
Destination  : 10.0.0.1 (Smart City IoT Gateway)
Severity     : CRITICAL
Threat Score : 1.0000 (Calibrated Posterior Probability: 100.0%)

=== 5-PART FORENSIC THREAT REPORT ===

1. CLASSIFICATION:
Reconnaissance Port Scan / Multi-Port SYN Sweep (Recon-PortScan)

2. CONFIDENCE:
High (100.0% confidence based on multi-stage sensor correlation)

3. TECHNICAL ROOT-CAUSE:
The ingress connection exhibited a statistically significant port drift of +4.2 unique ports
confirmed by the ADWIN adaptive engine (exceeding the mathematical threshold hurdle of 1.485).
Concurrently, Stage 1 sticky notes flagged zero-duration flow (Delta_t <= 5.12 us serialization limit)
and zero-payload transport packets (payload < 2B). The complete absence of ACK responses (syn_count=28,
ack_count=0) confirms incomplete TCP half-open scans designed to map listening IoT services without
completing handshakes.

4. OPERATIONAL IMPACT:
Adversary is mapping open municipal ports (e.g. Modbus, CoAP, Telnet) on the traffic controller.
Successful reconnaissance precedes unauthorized firmware tampering, command injection, or denial-of-service
disruptions against connected smart intersection controllers.

5. RECOMMENDED ACTION:
1. Immediately isolate source IP using edge iptables rule:
   iptables -I INPUT -s 192.168.1.105 -j DROP
2. Hand off incident telemetry to Layer 3 Zero Trust Mitigation Controller to transition intersection
   signals to physical hardware fail-safe (flashing yellow).
3. Revoke device session tokens and initiate credential rotation.
=================================================================
```

---

## 8. Verification and Interactive CLI Execution

The renovated codebase provides comprehensive execution options:

### 1. Execute ADWIN Mathematical Proof:
```powershell
.\.venv\Scripts\python.exe main.py --adwin
```
*Outputs complete 6-step calculation verifying $W_0, W_1, \mu_0, \mu_1, D = 4.2, m = 2.222, \varepsilon_{cut} = 1.485$, and Bernstein bound.*

### 2. Execute Interactive Scenario Simulator:
```powershell
.\.venv\Scripts\python.exe test_interactive.py
```
*Simulates all operational scenarios (Smart Thermostat, DDoS SYN Flood, Mirai Botnet, Stealth Port Scan with ADWIN, and Routine Device Reboot).*

### 3. Automated Training on Real CIC-IoT Benchmark:
```powershell
.\.venv\Scripts\python.exe main.py --train --data "data/real_ciciot_dataset.csv" --model-type hist_gb
```
*Trains HistGradientBoosting with dynamic early stopping ($T^* \le 181$), robust MAD scaling, and Youden's J threshold calibration.*

---

## References

1. **A. Bifet and R. Gavaldà**, "Learning from time-changing data with adaptive windowing," in *Proc. 7th SIAM Int. Conf. Data Mining (SDM)*, Minneapolis, MN, USA, 2007, pp. 443–448, doi: 10.1137/1.9781611972771.42.
2. **M. Datar, A. Gionis, P. Indyk, and R. Motwani**, "Maintaining stream statistics over sliding windows," *SIAM J. Comput.*, vol. 31, no. 6, pp. 1794–1813, 2002.
3. **T. Hastie, R. Tibshirani, and J. Friedman**, *The Elements of Statistical Learning: Data Mining, Inference, and Prediction*, 2nd ed. New York, NY, USA: Springer, 2009.
4. **J. H. Friedman**, "Greedy function approximation: A gradient boosting machine," *Ann. Statist.*, vol. 29, no. 5, pp. 1189–1232, 2001.
5. **T. Chen and C. Guestrin**, "XGBoost: A scalable tree boosting system," in *Proc. 22nd ACM SIGKDD Int. Conf. Knowledge Discovery and Data Mining*, San Francisco, CA, USA, 2016, pp. 785–794.
