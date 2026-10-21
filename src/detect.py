"""Inference and automated threat detection engine for incoming IoT traffic."""

import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

import joblib
import numpy as np
import pandas as pd

from src.config import ALERT_THRESHOLD, LOGS_DIR, MODEL_PATH
from src.preprocess import clean_dataframe
from src.llm_analyst import analyze_and_report

# ── ANSI terminal colors ──────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


class IoTTrafficDetector:
    """Automated detector that inspects network flows and classifies Normal vs. Abnormal traffic."""

    def __init__(self, model_path: Optional[Union[str, Path]] = None, threshold: float = ALERT_THRESHOLD):
        self.model_path = Path(model_path or MODEL_PATH)
        self.threshold = threshold

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Trained model artifact not found at '{self.model_path}'. "
                f"Please run the training pipeline first (e.g., `python main.py --train`)."
            )

        print(f"[*] Loading detection model pipeline from: {self.model_path}")
        artifact = joblib.load(self.model_path)
        self.model = artifact["model"]
        self.preprocessor = artifact["preprocessor"]
        self.features = artifact["features"]
        self.model_type = artifact.get("model_type", "unknown")
        print(f"[+] Loaded model ({self.model_type}) trained on {len(self.features)} features.")

    def detect_batch(
        self,
        traffic_data: Union[pd.DataFrame, str, Path],
        save_report: bool = True
    ) -> pd.DataFrame:
        """Analyze a batch of network flow traffic records."""
        if isinstance(traffic_data, (str, Path)):
            traffic_path = Path(traffic_data)
            if not traffic_path.exists():
                raise FileNotFoundError(f"Traffic file not found: {traffic_path}")
            print(f"[*] Reading incoming traffic batch from: {traffic_path}")
            df_raw = pd.read_csv(traffic_path, low_memory=False)
        else:
            df_raw = traffic_data.copy()

        df_clean = clean_dataframe(df_raw)

        # Scale and align features using saved preprocessor
        X_scaled = self.preprocessor.transform(df_clean)

        # Predict probabilities and classes
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(X_scaled)[:, 1]
        else:
            # Fallback for models without predict_proba
            predictions_raw = self.model.predict(X_scaled)
            probabilities = predictions_raw.astype(float)

        predictions = (probabilities >= self.threshold).astype(int)

        # Create structured detection results
        results = pd.DataFrame(index=df_clean.index)
        results["prediction"] = np.where(predictions == 1, "ABNORMAL", "NORMAL")
        results["anomaly_score"] = np.round(probabilities, 4)
        results["is_abnormal"] = predictions

        # Assign risk severity levels
        def get_risk(score: float) -> str:
            if score >= 0.90:
                return "CRITICAL"
            elif score >= 0.75:
                return "HIGH"
            elif score >= 0.50:
                return "MEDIUM"
            return "NORMAL"

        results["risk_level"] = results["anomaly_score"].apply(get_risk)

        # Retain original labels for verification if present
        for col in df_clean.columns:
            if col.lower() == "label":
                results["ground_truth_label"] = df_clean[col]
                break

        # Summary statistics
        total = len(results)
        abnormal_count = int((results["is_abnormal"] == 1).sum())
        normal_count = total - abnormal_count
        threat_pct = (abnormal_count / total * 100) if total > 0 else 0

        print("\n" + "=" * 55)
        print(f"{C.BOLD}{C.CYAN}          AUTOMATED TRAFFIC INSPECTION RESULTS{C.RESET}")
        print("=" * 55)
        print(f" Total Network Flows Inspected : {C.WHITE}{C.BOLD}{total:,}{C.RESET}")
        print(f" Normal Traffic Flows Identified : {C.GREEN}{normal_count:,} ({100 - threat_pct:.1f}%){C.RESET}")
        print(f" Abnormal Traffic (Threats)     : {C.RED}{C.BOLD}{abnormal_count:,} ({threat_pct:.1f}%){C.RESET}")
        print("-" * 55)
        print(f" Breakdown by Risk Level:")
        risk_counts = results["risk_level"].value_counts().to_dict()
        risk_colors = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.CYAN, "NORMAL": C.GREEN}
        for level in ["CRITICAL", "HIGH", "MEDIUM", "NORMAL"]:
            count = risk_counts.get(level, 0)
            color = risk_colors.get(level, C.WHITE)
            print(f"  - {color}{C.BOLD}{level:<10}{C.RESET}: {color}{count:,}{C.RESET}")
        print("=" * 55 + "\n")

        # Save audit logs
        if save_report:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_csv = LOGS_DIR / f"detection_log_{timestamp}.csv"
            # Combine raw data preview with detection results
            combined = pd.concat([results, df_raw], axis=1)
            combined.to_csv(report_csv, index=False)
            print(f"[+] Full detection audit log saved to: {report_csv}")

            # If threats were detected, save specific alert log
            if abnormal_count > 0:
                alerts_csv = LOGS_DIR / f"alerts_{timestamp}.csv"
                alerts = combined[combined["is_abnormal"] == 1]
                alerts.to_csv(alerts_csv, index=False)
                print(f"[!] Threat alerts isolated and logged to: {alerts_csv}")

                # Auto-trigger LLM analysis on top CRITICAL threats
                critical_alerts = results[results["risk_level"] == "CRITICAL"]
                if not critical_alerts.empty:
                    top_threats = critical_alerts.nlargest(min(3, len(critical_alerts)), "anomaly_score")
                    print(f"\n[*] Sending top {len(top_threats)} CRITICAL threat(s) to LLM analyst...")
                    # Get laptop real IP for Option C
                    import socket
                    try:
                        laptop_ip = socket.gethostbyname(socket.gethostname())
                    except Exception:
                        laptop_ip = "127.0.0.1"

                    for idx, row in top_threats.iterrows():
                        # Build alert dict from detection results + raw data
                        raw_row = df_raw.iloc[idx] if idx < len(df_raw) else {}
                        alert = {
                            "src_ip"       : str(raw_row.get("src_ip", raw_row.get("Src IP", laptop_ip))),
                            "dst_ip"       : str(raw_row.get("dst_ip", raw_row.get("Dst IP", "10.0.0.1 (Simulated IoT Gateway)"))),
                            "protocol"     : str(raw_row.get("Protocol Type", raw_row.get("protocol", "TCP"))),
                            "threat_score" : float(row["anomaly_score"]),
                            "severity"     : row["risk_level"],
                            "syn_count"    : int(raw_row.get("SYN Flag Cnt", raw_row.get("syn_count", 0))),
                            "ack_count"    : int(raw_row.get("ACK Flag Cnt", raw_row.get("ack_count", 0))),
                            "rst_count"    : int(raw_row.get("RST Flag Cnt", raw_row.get("rst_count", 0))),
                            "urg_count"    : int(raw_row.get("URG Flag Cnt", raw_row.get("urg_count", 0))),
                            "flow_duration": float(raw_row.get("flow_duration", raw_row.get("Flow Duration", 0))),
                            "packet_rate"  : float(raw_row.get("Rate", raw_row.get("packet_rate", 0))),
                            "flow_count"   : abnormal_count,
                        }
                        try:
                            analyze_and_report(alert)
                        except Exception as llm_err:
                            print(f"[!] LLM analysis skipped for flow {idx}: {llm_err}")

        return results

    def detect_single_flow(self, flow_dict: Dict[str, Union[float, int]]) -> Dict[str, Union[str, float, bool]]:
        """Inspect a single real-time network flow record."""
        df = pd.DataFrame([flow_dict])
        batch_res = self.detect_batch(df, save_report=False)
        row = batch_res.iloc[0]
        return {
            "prediction": row["prediction"],
            "anomaly_score": float(row["anomaly_score"]),
            "risk_level": row["risk_level"],
            "is_threat": bool(row["is_abnormal"] == 1),
        }
