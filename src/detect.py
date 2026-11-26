"""Inference, adaptive state tracking, and automated threat detection engine for IoT traffic.

Layer 2: AI-Powered Behavioral Anomaly Detection Pipeline
Stage 1: Feature Extraction & Adaptive State Tracking (Sticky Notes + ADWIN)
Stage 2: Preprocessing & Median Imputation
Stage 3: Robust Feature Standardization
Stage 5: Sigmoid Probability Scoring
Stage 6: Calibrated Operational Risk Triage
Stage 7: LLM Threat Analyst Agent Trigger (Capacity-Bounded Quantile)
Stage 8: Five-Part Forensic Threat Report Generation

Renovated based on Week 8 & Week 9 Progress Updates:
- Integrates Stage 1 sticky notes (is_inf_pkt_rate, is_nan_payload) and ADWIN port drift.
- Applies calibrated decision threshold tau* (derived from Youden's J / Bayes risk).
- Triages risk into confidence-interval and capacity-bounded tiers:
  Normal (P < tau*), Medium (tau* <= P < tau* + sigma_cal),
  High (tau* + sigma_cal <= P < tau_critical), Critical (P >= tau_critical).
- Escalates critical threats to LLM analyst based on token-budget quantile tau_critical.
"""

import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

import joblib
import numpy as np
import pandas as pd

from src.config import (
    ALERT_THRESHOLD,
    DEFAULT_CRITICAL_PERCENTILE,
    LOGS_DIR,
    MODEL_PATH,
)
from src.adwin import ADWINPortDriftEngine
from src.preprocess import clean_dataframe, extract_sticky_notes
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
    """Automated detector that inspects network flows using the renovated 8-stage pipeline."""

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        threshold: Optional[float] = None
    ):
        self.model_path = Path(model_path or MODEL_PATH)

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
        self.calibration = artifact.get("calibration", {})

        # Load calibrated decision threshold tau* (or fallback to parameter/config)
        if threshold is not None:
            self.threshold = float(threshold)
        elif "tau_optimal" in self.calibration:
            self.threshold = float(self.calibration["tau_optimal"])
        else:
            self.threshold = float(ALERT_THRESHOLD)

        # Calibrated risk triage cutoffs (Week 9 Stage 6)
        self.medium_cutoff = self.threshold
        self.high_cutoff = float(self.calibration.get("medium_upper_boundary", 0.75))
        self.critical_cutoff = float(self.calibration.get("tau_critical_llm", 0.90))

        # ADWIN Port Drift Engine for stream tracking
        self.adwin_engine = ADWINPortDriftEngine()

        print(
            f"[+] Loaded model ({self.model_type}) trained on {len(self.features)} features.\n"
            f"    - Calibrated Optimal Threshold (tau*): {self.threshold:.4f}\n"
            f"    - Risk Triage Boundaries: Normal < {self.medium_cutoff:.2f} <= "
            f"Medium < {self.high_cutoff:.2f} <= High < {self.critical_cutoff:.2f} <= Critical"
        )

    def get_risk_tier(self, score: float) -> str:
        """Map continuous anomaly probability to calibrated NIST/CVSS operational risk tier."""
        if score >= self.critical_cutoff:
            return "CRITICAL"
        elif score >= self.high_cutoff:
            return "HIGH"
        elif score >= self.medium_cutoff:
            return "MEDIUM"
        return "NORMAL"

    def detect_batch(
        self,
        traffic_data: Union[pd.DataFrame, str, Path],
        save_report: bool = True,
        trigger_llm: bool = True
    ) -> pd.DataFrame:
        """Analyze a batch of network flow traffic records through Stages 1 to 8."""
        if isinstance(traffic_data, (str, Path)):
            traffic_path = Path(traffic_data)
            if not traffic_path.exists():
                raise FileNotFoundError(f"Traffic file not found: {traffic_path}")
            print(f"[*] Reading incoming traffic batch from: {traffic_path}")
            df_raw = pd.read_csv(traffic_path, low_memory=False)
        else:
            df_raw = traffic_data.copy()

        df_clean = clean_dataframe(df_raw)

        # Stage 1 (Function 1): Compute physical-boundary heuristic sticky notes
        sticky_notes = extract_sticky_notes(df_clean)

        # Stage 1 (Function 2): Track ADWIN Port Drift if port column exists
        port_cols = [c for c in ["dst_port", "Dst Port", "destination_port"] if c in df_clean.columns]
        adwin_drifts = []
        if port_cols:
            self.adwin_engine.reset()
            for p in df_clean[port_cols[0]]:
                _, drift_val = self.adwin_engine.add_observation(p)
                adwin_drifts.append(drift_val)
        else:
            adwin_drifts = [0.0] * len(df_clean)

        # Stage 2 & 3: Robust scale and align features using saved preprocessor
        X_scaled = self.preprocessor.transform(df_clean)

        # Stage 5: Predict continuous probabilities using Logistic Sigmoid Link Function
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(X_scaled)[:, 1]
        else:
            predictions_raw = self.model.predict(X_scaled)
            probabilities = predictions_raw.astype(float)

        predictions = (probabilities >= self.threshold).astype(int)

        # Stage 6: Build structured detection results & triage operational risk
        results = pd.DataFrame(index=df_clean.index)
        results["prediction"] = np.where(predictions == 1, "ABNORMAL", "NORMAL")
        results["anomaly_score"] = np.round(probabilities, 4)
        results["is_abnormal"] = predictions
        results["risk_level"] = results["anomaly_score"].apply(self.get_risk_tier)

        # Attach Stage 1 & 2 sticky notes
        results["is_inf_pkt_rate"] = sticky_notes["is_inf_pkt_rate"]
        results["is_nan_payload"] = sticky_notes["is_nan_payload"]
        results["adwin_port_drift"] = adwin_drifts

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

        print("\n" + "=" * 60)
        print(f"{C.BOLD}{C.CYAN}       AI BEHAVIORAL DETECTION & RISK TRIAGE REPORT{C.RESET}")
        print("=" * 60)
        print(f" Total Network Flows Inspected : {C.WHITE}{C.BOLD}{total:,}{C.RESET}")
        print(f" Normal Flows (Permitted)      : {C.GREEN}{normal_count:,} ({100 - threat_pct:.1f}%){C.RESET}")
        print(f" Abnormal Flows (Threats)      : {C.RED}{C.BOLD}{abnormal_count:,} ({threat_pct:.1f}%){C.RESET}")
        print("-" * 60)
        print(f" Breakdown by Calibrated Operational Risk Tier:")
        risk_counts = results["risk_level"].value_counts().to_dict()
        risk_colors = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.CYAN, "NORMAL": C.GREEN}
        for level in ["CRITICAL", "HIGH", "MEDIUM", "NORMAL"]:
            count = risk_counts.get(level, 0)
            color = risk_colors.get(level, C.WHITE)
            print(f"  - {color}{C.BOLD}{level:<10}{C.RESET}: {color}{count:,}{C.RESET}")
        print("-" * 60)
        inf_count = int((results["is_inf_pkt_rate"] == 1.0).sum())
        nan_payload_count = int((results["is_nan_payload"] == 1.0).sum())
        print(f" Sticky Note Diagnostics:")
        print(f"  - Zero-Duration Probes (Delta_t <= 5.12us) : {inf_count:,}")
        print(f"  - Zero-Payload Probes (Payload < 2B)      : {nan_payload_count:,}")
        print("=" * 60 + "\n")

        # Save audit logs
        if save_report:
            try:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                report_csv = LOGS_DIR / f"detection_log_{timestamp}.csv"
                combined = pd.concat([results, df_raw], axis=1)
                combined.to_csv(report_csv, index=False)
                print(f"[+] Full detection audit log saved to: {report_csv}")

                # If threats were detected, save specific alert log for Layer 3 mitigation
                if abnormal_count > 0:
                    alerts_csv = LOGS_DIR / f"alerts_{timestamp}.csv"
                    alerts = combined[combined["is_abnormal"] == 1]
                    alerts.to_csv(alerts_csv, index=False)
                    print(f"[!] Threat alerts isolated and logged to: {alerts_csv}")
            except Exception as log_err:
                print(f"[*] Audit log export skipped ({log_err})")

            # Stage 7 & 8: Auto-trigger LLM analysis for CRITICAL threats (P >= tau_critical)
            if trigger_llm and abnormal_count > 0:
                    critical_alerts = results[results["risk_level"] == "CRITICAL"]
                    if not critical_alerts.empty:
                        top_threats = critical_alerts.nlargest(min(3, len(critical_alerts)), "anomaly_score")
                        print(f"\n[*] Triggering Stage 7 LLM Threat Analyst for top {len(top_threats)} CRITICAL threat(s)...")

                        import socket
                        try:
                            host_ip = socket.gethostbyname(socket.gethostname())
                        except Exception:
                            host_ip = "127.0.0.1"

                        for idx, row in top_threats.iterrows():
                            raw_row = df_raw.iloc[idx] if idx < len(df_raw) else {}
                            alert = {
                                "src_ip"         : str(raw_row.get("src_ip", raw_row.get("Src IP", host_ip))),
                                "dst_ip"         : str(raw_row.get("dst_ip", raw_row.get("Dst IP", "10.0.0.1 (IoT Gateway)"))),
                                "protocol"       : str(raw_row.get("Protocol Type", raw_row.get("protocol", "TCP"))),
                                "threat_score"   : float(row["anomaly_score"]),
                                "severity"       : row["risk_level"],
                                "syn_count"      : int(raw_row.get("SYN Flag Cnt", raw_row.get("syn_count", 0))),
                                "ack_count"      : int(raw_row.get("ACK Flag Cnt", raw_row.get("ack_count", 0))),
                                "rst_count"      : int(raw_row.get("RST Flag Cnt", raw_row.get("rst_count", 0))),
                                "urg_count"      : int(raw_row.get("URG Flag Cnt", raw_row.get("urg_count", 0))),
                                "flow_duration"  : float(raw_row.get("flow_duration", raw_row.get("Flow Duration", 0))),
                                "packet_rate"    : float(raw_row.get("Rate", raw_row.get("packet_rate", 0))),
                                "is_inf_pkt_rate": int(row["is_inf_pkt_rate"]),
                                "is_nan_payload" : int(row["is_nan_payload"]),
                                "adwin_port_drift": float(row["adwin_port_drift"]),
                                "flow_count"     : abnormal_count,
                            }
                            try:
                                analyze_and_report(alert)
                            except Exception as llm_err:
                                print(f"[!] LLM analysis skipped for flow {idx}: {llm_err}")

        return results

    def detect_single_flow(
        self,
        flow_dict: Dict[str, Union[float, int, str]],
        adwin_drift_val: float = 0.0
    ) -> Dict[str, Union[str, float, bool]]:
        """Inspect a single real-time network flow record with sticky notes and ADWIN drift."""
        df = pd.DataFrame([flow_dict])
        df_clean = clean_dataframe(df)

        sticky = extract_sticky_notes(df_clean)
        is_inf_rate = int(sticky["is_inf_pkt_rate"].iloc[0])
        is_nan_pld = int(sticky["is_nan_payload"].iloc[0])

        X_scaled = self.preprocessor.transform(df_clean)

        if hasattr(self.model, "predict_proba"):
            prob = float(self.model.predict_proba(X_scaled)[0, 1])
        else:
            prob = float(self.model.predict(X_scaled)[0])

        is_abnormal = bool(prob >= self.threshold)
        pred_label = "ABNORMAL" if is_abnormal else "NORMAL"
        risk_level = self.get_risk_tier(prob)

        return {
            "prediction": pred_label,
            "anomaly_score": round(prob, 4),
            "risk_level": risk_level,
            "is_threat": is_abnormal,
            "is_inf_pkt_rate": is_inf_rate,
            "is_nan_payload": is_nan_pld,
            "adwin_port_drift": float(adwin_drift_val),
        }
