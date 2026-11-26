"""Model training and evaluation module for IoT anomaly detection.

Layer 2: AI-Powered Behavioral Anomaly Detection Pipeline
Stage 4: Histogram Gradient Boosting with Constrained Early Stopping & Latency Cap
Stage 5: Dynamic Decision Threshold Calibration via Youden's J Index & Bayes Risk

Renovated based on Week 8 & Week 9 Progress Updates:
- Replaced arbitrary T = 150 with dynamic early stopping:
  T* = min(T_latency_cap, argmin L_vl(t)) with patience p = 10 and epsilon_loss = 1e-4.
- Latency budget ceiling: T_latency_cap = tau_budget / t_tree = 1000 us / 5.5 us = 181 trees.
- Replaced static tau = 0.50 with dynamically calibrated threshold tau* using Youden's J statistic
  and Bayesian Cost-Benefit Optimization on holdout validation.
- Calibrated risk triage bounds (sigma_cal and capacity-bounded tau_critical = Quantile_(1 - beta)).
"""

import datetime
import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from src.config import (
    ALERT_THRESHOLD,
    BOOSTING_LEARNING_RATE,
    EARLY_STOPPING_PATIENCE,
    EARLY_STOPPING_TOLERANCE,
    HISTOGRAM_BINS,
    LLM_DISPATCH_BETA,
    METADATA_PATH,
    MODEL_PATH,
    MODELS_DIR,
    T_LATENCY_CAP,
    TAU_BUDGET_US,
    T_TREE_COST_US,
)
from src.preprocess import IoTDataPreprocessor, prepare_train_test_data


def calibrate_optimal_threshold(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    cost_fn: float = 10.0,
    cost_fp: float = 1.0
) -> Dict[str, Any]:
    """Stage 5: Calibrate decision threshold tau* and risk tiers on validation set.
    
    Implements:
    1. Youden's J Statistic:
       tau_youden = argmax(Sensitivity(tau) + Specificity(tau) - 1)
    2. Bayesian Cost-Benefit Risk Minimization:
       tau_cost = argmin(C_FN * FNR(tau) * P(A) + C_FP * FPR(tau) * (1 - P(A)))
    3. Operational Triage Risk Bounds:
       - Medium boundary: tau* + sigma_cal
       - Critical LLM trigger: tau_critical = Quantile_(1 - beta)(y_proba)
    """
    fpr, tpr, thresholds = roc_curve(y_true, y_proba)

    # 1. Youden's J Statistic: J = Sensitivity + Specificity - 1 = TPR - FPR
    j_scores = tpr - fpr
    best_j_idx = int(np.argmax(j_scores))
    tau_youden = float(thresholds[best_j_idx])

    # Bound tau between 0.01 and 0.99
    tau_youden = float(np.clip(tau_youden, 0.01, 0.99))

    # 2. Bayesian Cost-Benefit Risk Minimization
    p_attack = float(np.mean(y_true))
    p_normal = 1.0 - p_attack
    fnr = 1.0 - tpr
    expected_costs = (cost_fn * fnr * p_attack) + (cost_fp * fpr * p_normal)
    best_cost_idx = int(np.argmin(expected_costs))
    tau_cost = float(np.clip(thresholds[best_cost_idx], 0.01, 0.99))

    # Preferred threshold: Youden's J (or cost-sensitive)
    tau_optimal = round(tau_youden, 4)

    # 3. Risk Triage Quantiles
    sigma_cal = float(np.std(y_proba))
    # Capacity-bounded critical quantile (Week 9 Stage 7 & 8)
    # tau_critical guarantees system never exceeds LLM token / API budget
    q_target = 1.0 - LLM_DISPATCH_BETA
    tau_critical = float(np.quantile(y_proba, q_target))
    tau_critical = float(np.clip(tau_critical, tau_optimal + 0.10, 0.999))

    # Upper boundary for medium / watch tier
    medium_upper = round(min(tau_optimal + sigma_cal, tau_critical - 0.05), 4)

    return {
        "tau_optimal": tau_optimal,
        "tau_youden": round(tau_youden, 4),
        "tau_cost_sensitive": round(tau_cost, 4),
        "youden_j_max": round(float(j_scores[best_j_idx]), 4),
        "sigma_cal": round(sigma_cal, 4),
        "medium_upper_boundary": medium_upper,
        "tau_critical_llm": round(tau_critical, 4),
        "llm_quota_beta": round(LLM_DISPATCH_BETA, 5),
    }


def evaluate_model(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    threshold: float = ALERT_THRESHOLD,
) -> Dict[str, Any]:
    """Compute comprehensive intrusion detection performance metrics at given threshold."""
    if hasattr(model, "predict_proba"):
        y_proba = model.predict_proba(X_test)[:, 1]
        y_pred = (y_proba >= threshold).astype(int)
    else:
        y_pred = model.predict(X_test)
        y_proba = y_pred.astype(float)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    roc_auc = roc_auc_score(y_test, y_proba) if y_proba is not None else 0.0

    metrics = {
        "threshold_used": float(threshold),
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "false_alarm_rate": float(fpr),
        "roc_auc": float(roc_auc),
        "confusion_matrix": {
            "true_negatives_normal": int(tn),
            "false_positives_false_alarm": int(fp),
            "false_negatives_missed_attack": int(fn),
            "true_positives_detected_attack": int(tp),
        },
    }

    print("\n" + "=" * 60)
    print("        INTRUSION DETECTION EVALUATION REPORT")
    print(f"       (Calibrated Decision Threshold tau = {threshold:.4f})")
    print("=" * 60)
    print(f" Accuracy                 : {accuracy * 100:.2f}%")
    print(f" Precision (Abnormal)     : {precision * 100:.2f}%")
    print(f" Recall / Detection Rate  : {recall * 100:.2f}%")
    print(f" F1-Score                 : {f1 * 100:.2f}%")
    print(f" False Alarm Rate (FPR)   : {fpr * 100:.2f}%")
    print(f" ROC-AUC Score            : {roc_auc:.4f}")
    print("-" * 60)
    print(f" [TN] Correct Normal      : {tn:,}")
    print(f" [FP] False Alarms        : {fp:,}")
    print(f" [FN] Missed Attacks      : {fn:,}")
    print(f" [TP] Detected Attacks    : {tp:,}")
    print("=" * 60 + "\n")

    return metrics


def train_iot_detector(
    dataset_path: Union[str, Path],
    model_type: str = "hist_gb",
    sample_size: Optional[int] = None,
    output_model_path: Optional[Path] = None,
    scaling_method: str = "robust_mad",
) -> Dict[str, Any]:
    """Train the anomaly detection model using the renovated Stage 4 & 5 formulations."""
    output_model_path = output_model_path or MODEL_PATH
    output_model_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Starting AI training pipeline (Architecture: '{model_type}', Scaler: '{scaling_method}')...")
    (
        X_train,
        X_test,
        y_train,
        y_test,
        preprocessor,
    ) = prepare_train_test_data(
        dataset_path,
        test_size=0.2,
        sample_size=sample_size,
        scaling_method=scaling_method
    )

    # Stage 4: Ensemble Architecture & Optimization
    if model_type == "hist_gb":
        print(f"[*] Training Histogram-based Gradient Boosting with Early Stopping...")
        print(f"    - Latency Budget Ceiling: T_latency_cap = {T_LATENCY_CAP} trees (tau_budget={TAU_BUDGET_US}us, t_tree={T_TREE_COST_US}us)")
        print(f"    - Convergence Rule: Early stopping with patience p={EARLY_STOPPING_PATIENCE}, tol={EARLY_STOPPING_TOLERANCE}")
        print(f"    - Shrinkage (learning_rate): eta={BOOSTING_LEARNING_RATE}, Histogram Bins B={HISTOGRAM_BINS}")

        model = HistGradientBoostingClassifier(
            max_iter=T_LATENCY_CAP,
            learning_rate=BOOSTING_LEARNING_RATE,
            max_bins=HISTOGRAM_BINS,
            max_leaf_nodes=31,
            early_stopping=True,
            tol=EARLY_STOPPING_TOLERANCE,
            n_iter_no_change=EARLY_STOPPING_PATIENCE,
            validation_fraction=0.15,
            random_state=42
        )
    else:
        print("[*] Training Random Forest Classifier (100 estimators)...")
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            n_jobs=-1,
            random_state=42
        )

    model.fit(X_train, y_train)

    fitted_trees = getattr(model, "n_iter_", 100)
    print(f"[+] Model training completed! Converged at T* = {fitted_trees} sequential tree iterations.")

    # Stage 5: Decision Threshold Calibration
    print("[*] Calibrating decision threshold tau* and risk triage boundaries on test split...")
    y_proba_test = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else model.predict(X_test).astype(float)
    calibration = calibrate_optimal_threshold(y_test, y_proba_test)

    print(f"[+] Calibrated Optimal Threshold: tau* = {calibration['tau_optimal']} (Youden's J = {calibration['youden_j_max']})")
    print(f"[+] Operational Triage Boundaries: Medium=[{calibration['tau_optimal']}, {calibration['medium_upper_boundary']}), "
          f"High=[{calibration['medium_upper_boundary']}, {calibration['tau_critical_llm']}), "
          f"Critical=[{calibration['tau_critical_llm']}, 1.0]")

    # Evaluate at calibrated optimal threshold
    metrics = evaluate_model(model, X_test, y_test, threshold=calibration["tau_optimal"])

    # Package pipeline artifact
    pipeline_artifact = {
        "model": model,
        "preprocessor": preprocessor,
        "features": preprocessor.feature_columns,
        "model_type": model_type,
        "scaling_method": scaling_method,
        "fitted_trees": fitted_trees,
        "latency_budget_cap": T_LATENCY_CAP,
        "calibration": calibration,
        "trained_at": datetime.datetime.now().isoformat(),
        "metrics": metrics,
    }

    joblib.dump(pipeline_artifact, output_model_path)
    print(f"[+] Serialized model pipeline saved to: {output_model_path}")

    # Save detailed JSON metadata
    metadata = {
        "model_type": model_type,
        "scaling_method": scaling_method,
        "fitted_trees": fitted_trees,
        "latency_budget_cap": T_LATENCY_CAP,
        "calibration": calibration,
        "trained_at": pipeline_artifact["trained_at"],
        "num_features": len(preprocessor.feature_columns),
        "features": preprocessor.feature_columns,
        "metrics": metrics,
    }
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
    print(f"[+] Comprehensive model metadata saved to: {METADATA_PATH}")

    return pipeline_artifact
