"""Configuration settings for IoT Network Intrusion Detection System (IDS).

Layer 2: AI-Powered Behavioral Anomaly Detection Pipeline
Concordia University Research Project

Renovated based on Week 8 & Week 9 Progress Updates:
Replaced all heuristic 'magic numbers' with mathematically defensible,
adaptive formulations grounded in statistical learning and physical networking constraints.
"""

from pathlib import Path
import math

# ═══════════════════════════════════════════════════════════════
# 1. Base Project Paths
# ═══════════════════════════════════════════════════════════════
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

# Auto-detect external dataset directory (prioritizing D:\CSV)
if Path("D:/CSV/CSV").exists():
    EXTERNAL_DATA_DIR = Path("D:/CSV/CSV")
elif Path("D:/CSV").exists():
    EXTERNAL_DATA_DIR = Path("D:/CSV")
else:
    EXTERNAL_DATA_DIR = Path("D:/IoT_Data")

MODELS_DIR = PROJECT_ROOT / "models"
LOGS_DIR = PROJECT_ROOT / "logs"

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
if Path("D:/").exists():
    try:
        EXTERNAL_DATA_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
MODELS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Model Artifact Paths
MODEL_PATH = MODELS_DIR / "iot_anomaly_detector.joblib"
METADATA_PATH = MODELS_DIR / "model_metadata.json"

# ═══════════════════════════════════════════════════════════════
# 2. Dataset Feature Schema & Ground-Truth Labels
# ═══════════════════════════════════════════════════════════════
BENIGN_LABELS = {
    "benigntraffic",
    "benign",
    "normal",
    "0",
    0
}

# The 46 standard flow features in CIC-IoT2023 benchmark
CICIOT2023_FEATURES = [
    "flow_duration", "Header_Length", "Protocol Type", "Duration",
    "Rate", "Srate", "Drate", "fin_flag_number", "syn_flag_number",
    "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ece_flag_number", "cwr_flag_number", "ack_count", "syn_count",
    "fin_count", "urg_count", "rst_count", "HTTP", "HTTPS", "DNS",
    "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP", "ARP",
    "ICMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG", "Std",
    "Tot size", "IAT", "Number", "Magnitue", "Radius", "Covariance",
    "Variance", "Weight"
]

TARGET_COLUMN = "label"

# ═══════════════════════════════════════════════════════════════
# 3. Scientifically Justified Parameters (Week 8 & Week 9 Renovations)
#    Replacing Magic Numbers across the 8-Stage Architecture
# ═══════════════════════════════════════════════════════════════

# ── Cluster 1: ADWIN Drift Detection Constants (Stage 1) ──
# Instead of arbitrary delta = 0.002, anchor delta to Target False Alarm Rate (SLA)
# over an operational horizon of N_horizon evaluations:
# delta = 1 - (1 - alpha_target)^(1 / N_horizon) approx alpha_target / N_horizon
ALPHA_TARGET = 0.05                  # Target false alarm probability per operational horizon
N_HORIZON = 50_000                   # Operational evaluation horizon (flows per monitoring period)
ADWIN_DELTA_SLA = ALPHA_TARGET / N_HORIZON  # 1.0e-6 (SLA-anchored confidence)
ADWIN_DELTA_BENCHMARK = 0.002        # Benchmark confidence setting from Week 8 calculation
ADWIN_DEFAULT_R = 10.0               # Default observation range R (ports 0-10 or unique counts)

# ── Cluster 2: Imputation & Heuristic Sticky Notes (Stages 1 & 2) ──
# Physical Timestamp Resolution Boundary:
# On a 100 Mbps link with a 64-byte minimum frame, serialization delay = 512 bits / 10^8 bps = 5.12 us.
NIC_CLOCK_RESOLUTION_SEC = 1.0e-6    # 1.0 us NIC timer resolution
LINK_BANDWIDTH_BPS = 1.0e8           # 100 Mbps physical link bandwidth
MIN_FRAME_SIZE_BYTES = 64            # 64 bytes Ethernet minimum frame
SERIALIZATION_DELAY_SEC = (MIN_FRAME_SIZE_BYTES * 8) / LINK_BANDWIDTH_BPS  # 5.12 us
EPSILON_TIME_BOUND = max(NIC_CLOCK_RESOLUTION_SEC, SERIALIZATION_DELAY_SEC)  # 5.12e-6 s

# Minimum application protocol payload size (e.g., 2 bytes for MQTT fixed header)
MIN_APP_PAYLOAD_BYTES = 2.0

# ── Cluster 3: Robust Feature Standardization (Stage 3) ──
# Chebyshev's Inequality: P(|X - mu| >= k * sigma) <= 1 / k^2
# Allows P_tail_allowance (0.1%) extreme tail representation:
# k_clip = sqrt(1 / P_tail_allowance) approx 31.623 (replaces arbitrary [-5.0, +5.0])
P_TAIL_ALLOWANCE = 0.001
CHEBYSHEV_K_CLIP = math.sqrt(1.0 / P_TAIL_ALLOWANCE)  # approx 31.6227766

# ── Cluster 4: Ensemble Sizing & Optimization (Stage 4) ──
# Edge Hardware Latency Budget Ceiling:
# Maximum inference budget tau_budget = 1.0 ms (1000 us); average tree traversal cost = 5.5 us.
TAU_BUDGET_US = 1000.0               # 1.0 ms latency budget
T_TREE_COST_US = 5.5                 # 5.5 us per tree traversal
T_LATENCY_CAP = int(TAU_BUDGET_US // T_TREE_COST_US)  # 181 trees ceiling
EARLY_STOPPING_PATIENCE = 10         # Consecutive trees without improvement
EARLY_STOPPING_TOLERANCE = 1.0e-4    # epsilon_loss = 1e-4
BOOSTING_LEARNING_RATE = 0.10        # Shrinkage eta = 0.10
HISTOGRAM_BINS = 256                 # Discretization bins B = 256

# ── Cluster 5: Decision Threshold Calibration (Stage 5) ──
# Default fallback; calibrated dynamically on validation ROC via Youden's J statistic
# tau* = argmax(Sensitivity(tau) + Specificity(tau) - 1)
DEFAULT_ALERT_THRESHOLD = 0.50
ALERT_THRESHOLD = DEFAULT_ALERT_THRESHOLD

# ── Cluster 6 & 7: Operational Risk Triage & LLM Escalation Tiers (Stages 6, 7 & 8) ──
# Critical dispatch threshold derived from LLM token capacity and hourly dispatch quota:
# beta = (LLM API Quota per Hour) / (Expected Alerts per Hour) = 20 / 10,000 = 0.002
LLM_QUOTA_PER_HOUR = 20
EXPECTED_ALERTS_PER_HOUR = 10_000
LLM_DISPATCH_BETA = LLM_QUOTA_PER_HOUR / EXPECTED_ALERTS_PER_HOUR  # 0.002
DEFAULT_CRITICAL_PERCENTILE = 1.0 - LLM_DISPATCH_BETA              # 99.8th percentile
