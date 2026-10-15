"""Configuration settings for IoT Network Intrusion Detection System (IDS)."""

from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
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

# Label Configuration
BENIGN_LABELS = {
    "benigntraffic",
    "benign",
    "normal",
    "0",
    0
}

# The 46 standard flow features in CIC-IoT2023
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

# Detection threshold (Probability above which traffic is flagged as Abnormal)
ALERT_THRESHOLD = 0.50
