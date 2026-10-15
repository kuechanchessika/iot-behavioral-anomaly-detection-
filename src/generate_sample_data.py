"""Synthetic sample data generator adhering to the official CIC-IoT2023 schema."""

from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

from src.config import CICIOT2023_FEATURES, DATA_DIR


def generate_sample_iot_dataset(
    num_samples: int = 5000,
    abnormal_ratio: float = 0.35,
    output_path: Optional[Path] = None,
    random_state: int = 42,
) -> pd.DataFrame:
    """Generate realistic synthetic IoT network flows mimicking the CIC-IoT2023 distribution."""
    rng = np.random.default_rng(random_state)
    output_path = output_path or (DATA_DIR / "sample_ciciot2023.csv")

    num_abnormal = int(num_samples * abnormal_ratio)
    num_normal = num_samples - num_abnormal

    # Normal baseline IoT characteristics: regular periodic heartbeats, low jitter, standard MQTT/HTTP/CoAP/DNS
    data_dict = {}

    # Flow timing metrics
    normal_dur = rng.exponential(scale=1.5, size=num_normal)
    abnormal_dur = np.concatenate([
        rng.exponential(scale=0.01, size=num_abnormal // 2),  # Fast burst floods (DDoS/DoS)
        rng.exponential(scale=60.0, size=num_abnormal - num_abnormal // 2),  # Long botnet connections / slowloris
    ])
    data_dict["flow_duration"] = np.concatenate([normal_dur, abnormal_dur])
    data_dict["Duration"] = data_dict["flow_duration"]

    # Header length
    normal_hl = rng.integers(20, 60, size=num_normal)
    abnormal_hl = rng.integers(20, 1500, size=num_abnormal)
    data_dict["Header_Length"] = np.concatenate([normal_hl, abnormal_hl])

    # Protocol Type (TCP=6, UDP=17, ICMP=1)
    normal_proto = rng.choice([6.0, 17.0], size=num_normal, p=[0.7, 0.3])
    abnormal_proto = rng.choice([6.0, 17.0, 1.0], size=num_abnormal, p=[0.4, 0.4, 0.2])
    data_dict["Protocol Type"] = np.concatenate([normal_proto, abnormal_proto])

    # Packet Rates
    normal_rate = rng.gamma(shape=2.0, scale=5.0, size=num_normal)
    abnormal_rate = rng.gamma(shape=10.0, scale=100.0, size=num_abnormal)  # Attack flood rates
    data_dict["Rate"] = np.concatenate([normal_rate, abnormal_rate])
    data_dict["Srate"] = data_dict["Rate"] * rng.uniform(0.5, 1.0, size=num_samples)
    data_dict["Drate"] = data_dict["Rate"] * rng.uniform(0.0, 0.5, size=num_samples)

    # TCP Flags
    for flag in ["fin_flag_number", "rst_flag_number", "psh_flag_number", "ece_flag_number", "cwr_flag_number"]:
        data_dict[flag] = rng.choice([0.0, 1.0], size=num_samples, p=[0.95, 0.05])

    # SYN flag number (high in SYN floods and portscans)
    normal_syn = rng.choice([0.0, 1.0], size=num_normal, p=[0.9, 0.1])
    abnormal_syn = rng.choice([0.0, 1.0], size=num_abnormal, p=[0.3, 0.7])
    data_dict["syn_flag_number"] = np.concatenate([normal_syn, abnormal_syn])

    # ACK flag number
    data_dict["ack_flag_number"] = rng.choice([0.0, 1.0], size=num_samples, p=[0.2, 0.8])

    # Flag counts
    data_dict["ack_count"] = rng.poisson(lam=10.0, size=num_samples)
    data_dict["syn_count"] = np.concatenate([
        rng.poisson(lam=1.0, size=num_normal),
        rng.poisson(lam=25.0, size=num_abnormal),
    ])
    data_dict["fin_count"] = rng.poisson(lam=1.0, size=num_samples)
    data_dict["urg_count"] = rng.poisson(lam=0.1, size=num_samples)
    data_dict["rst_count"] = np.concatenate([
        rng.poisson(lam=0.2, size=num_normal),
        rng.poisson(lam=5.0, size=num_abnormal),
    ])

    # Protocol flags (HTTP, HTTPS, DNS, Telnet, SSH, etc.)
    services = ["HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC"]
    for srv in services:
        if srv in ["HTTP", "HTTPS", "DNS", "TCP", "UDP"]:
            data_dict[srv] = rng.choice([0.0, 1.0], size=num_samples, p=[0.6, 0.4])
        elif srv in ["Telnet", "SSH"]:
            # Telnet/SSH often hit in brute-force Mirai IoT attacks
            norm_srv = rng.choice([0.0, 1.0], size=num_normal, p=[0.98, 0.02])
            abnorm_srv = rng.choice([0.0, 1.0], size=num_abnormal, p=[0.6, 0.4])
            data_dict[srv] = np.concatenate([norm_srv, abnorm_srv])
        else:
            data_dict[srv] = rng.choice([0.0, 1.0], size=num_samples, p=[0.9, 0.1])

    # Packet Sizes & Statistical aggregates
    normal_tot_sum = rng.normal(loc=1200, scale=300, size=num_normal)
    abnormal_tot_sum = rng.normal(loc=15000, scale=5000, size=num_abnormal)
    data_dict["Tot sum"] = np.maximum(0, np.concatenate([normal_tot_sum, abnormal_tot_sum]))

    data_dict["Min"] = rng.uniform(40, 64, size=num_samples)
    data_dict["Max"] = rng.uniform(100, 1500, size=num_samples)
    data_dict["AVG"] = (data_dict["Min"] + data_dict["Max"]) / 2
    data_dict["Std"] = rng.uniform(5, 200, size=num_samples)
    data_dict["Tot size"] = data_dict["Tot sum"]
    data_dict["IAT"] = rng.exponential(scale=0.05, size=num_samples)
    data_dict["Number"] = rng.poisson(lam=15, size=num_samples)
    data_dict["Magnitue"] = np.sqrt(data_dict["AVG"])
    data_dict["Radius"] = data_dict["Std"] / 2
    data_dict["Covariance"] = rng.normal(0, 10, size=num_samples)
    data_dict["Variance"] = rng.uniform(1, 100, size=num_samples)
    data_dict["Weight"] = rng.uniform(0.1, 1.0, size=num_samples)

    # Ensure all 46 features are present
    for feat in CICIOT2023_FEATURES:
        if feat not in data_dict:
            data_dict[feat] = rng.uniform(0.0, 1.0, size=num_samples)

    # Construct target Labels
    attack_types = [
        "DDoS-UDP_Flood", "DDoS-TCP_Flood", "DDoS-SYN_Flood",
        "Mirai-greeth_ip", "Recon-PortScan", "VulnerabilityScan",
        "DictionaryBruteForce", "MITM-ArpSpoofing"
    ]
    normal_labels = ["BenignTraffic"] * num_normal
    abnormal_labels = list(rng.choice(attack_types, size=num_abnormal))
    data_dict["label"] = normal_labels + abnormal_labels

    df = pd.DataFrame(data_dict)

    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[+] Generated sample dataset ({len(df)} records) saved to: {output_path}")

    return df


if __name__ == "__main__":
    generate_sample_iot_dataset()
