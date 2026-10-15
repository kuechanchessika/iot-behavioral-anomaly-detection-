"""Model training and evaluation module for IoT anomaly detection."""

import datetime
import json
from pathlib import Path
from typing import Any, Dict, Optional, Union

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
)

from src.config import MODEL_PATH, METADATA_PATH, MODELS_DIR
from src.preprocess import IoTDataPreprocessor, prepare_train_test_data


def evaluate_model(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray
) -> Dict[str, Union[float, list]]:
    """Compute comprehensive intrusion detection performance metrics."""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)  # Detection Rate
    f1 = f1_score(y_test, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0  # False Alarm Rate
    roc_auc = roc_auc_score(y_test, y_proba) if y_proba is not None else 0.0

    metrics = {
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

    print("\n" + "=" * 55)
    print("        INTRUSION DETECTION EVALUATION REPORT")
    print("=" * 55)
    print(f" Accuracy                 : {accuracy * 100:.2f}%")
    print(f" Precision (Abnormal)     : {precision * 100:.2f}%")
    print(f" Recall / Detection Rate  : {recall * 100:.2f}%")
    print(f" F1-Score                 : {f1 * 100:.2f}%")
    print(f" False Alarm Rate (FPR)   : {fpr * 100:.2f}%")
    print(f" ROC-AUC Score            : {roc_auc:.4f}")
    print("-" * 55)
    print(f" [TN] Correct Normal      : {tn:,}")
    print(f" [FP] False Alarms        : {fp:,}")
    print(f" [FN] Missed Attacks      : {fn:,}")
    print(f" [TP] Detected Attacks    : {tp:,}")
    print("=" * 55 + "\n")

    return metrics


def train_iot_detector(
    dataset_path: Union[str, Path],
    model_type: str = "random_forest",
    sample_size: Optional[int] = None,
    output_model_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Train an anomaly detection model on an IoT network dataset."""
    output_model_path = output_model_path or MODEL_PATH
    output_model_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Starting AI training pipeline using model architecture: '{model_type}'...")
    (
        X_train,
        X_test,
        y_train,
        y_test,
        preprocessor,
    ) = prepare_train_test_data(dataset_path, test_size=0.2, sample_size=sample_size)

    # Initialize model
    if model_type == "hist_gb":
        print("[*] Training Histogram-based Gradient Boosting Classifier...")
        model = HistGradientBoostingClassifier(
            max_iter=150,
            learning_rate=0.1,
            max_leaf_nodes=31,
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
    print("[+] Model training completed!")

    # Evaluate model
    print("[*] Evaluating model performance on holdout test set...")
    metrics = evaluate_model(model, X_test, y_test)

    # Package pipeline artifact
    pipeline_artifact = {
        "model": model,
        "preprocessor": preprocessor,
        "features": preprocessor.feature_columns,
        "model_type": model_type,
        "trained_at": datetime.datetime.now().isoformat(),
        "metrics": metrics,
    }

    joblib.dump(pipeline_artifact, output_model_path)
    print(f"[+] Model pipeline successfully saved to: {output_model_path}")

    # Save readable JSON metadata
    metadata = {
        "model_type": model_type,
        "trained_at": pipeline_artifact["trained_at"],
        "num_features": len(preprocessor.feature_columns),
        "features": preprocessor.feature_columns,
        "metrics": metrics,
    }
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
    print(f"[+] Model metadata saved to: {METADATA_PATH}")

    return pipeline_artifact
