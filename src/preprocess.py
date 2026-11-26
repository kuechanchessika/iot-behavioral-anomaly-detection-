"""Data preprocessing and feature pipeline for IoT traffic analysis.

Layer 2: AI-Powered Behavioral Anomaly Detection Pipeline
Stage 1: Feature Extraction & Adaptive State Tracking (Sticky Notes & ADWIN)
Stage 2: Preprocessing & Median Imputation
Stage 3: Robust Feature Standardization (MAD & Chebyshev Outlier Clipping)

Renovated based on Week 8 & Week 9 Progress Updates:
- Replaced standard Z-score with Median Absolute Deviation (MAD) robust scaling.
- Replaced arbitrary [-5.0, +5.0] clamping with Chebyshev's Inequality envelope (k_clip = sqrt(1 / P_tail) approx 31.62).
- Added physical serialization delay boundary (epsilon_t = 5.12 us) for is_inf_pkt_rate sticky note.
- Added application transport-layer boundary (L_min_app = 2 bytes) for is_nan_payload sticky note.
- Median imputation preserves sticky note flags without erasure.
"""

import json
import math
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from src.config import (
    BENIGN_LABELS,
    CICIOT2023_FEATURES,
    TARGET_COLUMN,
    CHEBYSHEV_K_CLIP,
    EPSILON_TIME_BOUND,
    MIN_APP_PAYLOAD_BYTES,
    P_TAIL_ALLOWANCE,
)


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Clean column names and strip extraneous whitespace."""
    df = df.copy()
    df.columns = df.columns.str.strip()
    return df


def extract_sticky_notes(
    df: pd.DataFrame,
    epsilon_t: float = EPSILON_TIME_BOUND,
    l_min_app: float = MIN_APP_PAYLOAD_BYTES
) -> pd.DataFrame:
    """Stage 1 (Function 1): Compute physical-boundary heuristic sticky notes.
    
    1. Zero-Duration Boundary: is_inf_pkt_rate = 1 if Delta_t <= epsilon_t (5.12 us).
       Grounded in Ethernet serialization delay on 100 Mbps links.
    2. Zero-Payload Boundary: is_nan_payload = 1 if payload < L_min_app (2 bytes).
       Grounded in MQTT/transport control packet structure.
    """
    df_sticky = pd.DataFrame(index=df.index)

    # 1. Inspect flow duration / timing
    duration_col = None
    for candidate in ["flow_duration", "Duration", "flow duration"]:
        if candidate in df.columns:
            duration_col = candidate
            break

    rate_col = None
    for candidate in ["Rate", "rate", "packet_rate"]:
        if candidate in df.columns:
            rate_col = candidate
            break

    if duration_col is not None:
        dur = pd.to_numeric(df[duration_col], errors="coerce").fillna(0.0)
        # Check if flow duration is less than or equal to physical serialization delay
        is_zero_dur = (dur <= epsilon_t) | np.isclose(dur, 0.0, atol=1e-7)
    else:
        is_zero_dur = pd.Series(False, index=df.index)

    if rate_col is not None:
        rate = pd.to_numeric(df[rate_col], errors="coerce")
        is_inf_rate = np.isinf(rate) | (rate >= 1e7)
    else:
        is_inf_rate = pd.Series(False, index=df.index)

    df_sticky["is_inf_pkt_rate"] = np.where(is_zero_dur | is_inf_rate, 1.0, 0.0)

    # 2. Inspect payload size
    payload_cols = [c for c in ["Tot size", "Tot sum", "Min", "Max"] if c in df.columns]
    if payload_cols:
        min_payload = pd.to_numeric(df[payload_cols[0]], errors="coerce").fillna(0.0)
        is_empty_payload = (min_payload < l_min_app) | np.isnan(min_payload)
    else:
        is_empty_payload = pd.Series(False, index=df.index)

    df_sticky["is_nan_payload"] = np.where(is_empty_payload, 1.0, 0.0)

    return df_sticky


def encode_labels(labels: pd.Series) -> pd.Series:
    """Convert raw labels into binary format: 0 for Normal (Benign), 1 for Abnormal (Attack)."""
    cleaned_labels = labels.astype(str).str.strip().str.lower()
    is_benign = cleaned_labels.isin(BENIGN_LABELS)
    binary_labels = np.where(is_benign, 0, 1)
    return pd.Series(binary_labels, index=labels.index, name="is_abnormal")


class IoTDataPreprocessor:
    """Stage 2 & 3: Preprocessing, Median Imputation, and Robust Feature Standardization.
    
    Implements:
    - Stage 2: Median imputation replacing NaN and Inf without erasing sticky notes.
    - Stage 3: Robust Median Absolute Deviation (MAD) scaling:
               z_robust = (x - median) / (MAD * 1.4826)
    - Stage 3: Chebyshev's Inequality outlier clipping envelope:
               k_clip = sqrt(1 / P_tail_allowance) approx 31.62
               Preserves proportional magnitude of severe attacks while controlling extremes.
    """

    def __init__(
        self,
        feature_columns: Optional[List[str]] = None,
        method: str = "robust_mad",
        k_clip: float = CHEBYSHEV_K_CLIP,
    ):
        self.feature_columns = feature_columns or CICIOT2023_FEATURES
        self.method = method
        self.k_clip = k_clip

        # Statistical parameters learned on training split (to prevent data leakage)
        self.impute_values: Dict[str, float] = {}
        self.medians: Dict[str, float] = {}
        self.scales: Dict[str, float] = {}
        self.mads: Dict[str, float] = {}
        self.means: Dict[str, float] = {}
        self.stds: Dict[str, float] = {}

        # Fallback StandardScaler for comparison
        self.standard_scaler: StandardScaler = StandardScaler()
        self.is_fitted: bool = False

    def fit(self, X: pd.DataFrame) -> "IoTDataPreprocessor":
        """Compute robust medians, MAD scaling, and imputation parameters from training data."""
        X_clean = clean_dataframe(X)
        aligned_features = self._align_features(X_clean)

        for col in self.feature_columns:
            series = aligned_features[col]
            valid_vals = series.dropna()

            # 1. Median Imputation Parameter (Stage 2)
            if len(valid_vals) > 0:
                col_median = float(valid_vals.median())
                col_mean = float(valid_vals.mean())
                col_std = float(valid_vals.std())
            else:
                col_median = 0.0
                col_mean = 0.0
                col_std = 1.0

            if np.isnan(col_median):
                col_median = 0.0
            if np.isnan(col_mean):
                col_mean = 0.0
            if np.isnan(col_std) or col_std <= 0:
                col_std = 1.0

            self.impute_values[col] = col_median
            self.medians[col] = col_median
            self.means[col] = col_mean
            self.stds[col] = col_std

            # 2. Median Absolute Deviation (MAD) Parameter (Stage 3)
            # MAD = median(|x_i - median(X)|)
            abs_deviations = (valid_vals - col_median).abs()
            mad = float(abs_deviations.median()) if len(abs_deviations) > 0 else 0.0
            if np.isnan(mad):
                mad = 0.0
            self.mads[col] = mad

            # Consistent normal estimator scale: MAD * 1.4826
            scale = mad * 1.4826
            # If MAD is zero (e.g., discrete binary flags), fallback to standard deviation
            if scale < 1e-6:
                scale = col_std
            if scale < 1e-6:
                scale = 1.0  # Constant column fallback

            self.scales[col] = scale

        # Also fit standard scaler for dual evaluation
        imputed_df = aligned_features.copy()
        for col in self.feature_columns:
            imputed_df[col] = imputed_df[col].fillna(self.impute_values[col])
        self.standard_scaler.fit(imputed_df[self.feature_columns])

        self.is_fitted = True
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Apply feature alignment, median imputation, and robust scaling."""
        if not getattr(self, "is_fitted", False):
            raise RuntimeError("Preprocessor must be fitted before calling transform.")

        X_clean = clean_dataframe(X)
        aligned_features = self._align_features(X_clean)

        # Stage 2: Impute missing values using stored training medians
        impute_map = getattr(self, "impute_values", {})
        for col in self.feature_columns:
            aligned_features[col] = aligned_features[col].fillna(impute_map.get(col, 0.0))

        method = getattr(self, "method", "zscore")
        if method == "robust_mad" and hasattr(self, "medians") and hasattr(self, "scales"):
            # Stage 3: Robust MAD standardization: z_robust = (x - median) / scale
            scaled_matrix = np.zeros((len(aligned_features), len(self.feature_columns)), dtype=np.float32)
            k_clip = getattr(self, "k_clip", CHEBYSHEV_K_CLIP)
            for idx, col in enumerate(self.feature_columns):
                raw_col = aligned_features[col].to_numpy(dtype=np.float32)
                med = self.medians.get(col, 0.0)
                scale = self.scales.get(col, 1.0)
                z = (raw_col - med) / scale

                # Stage 3: Chebyshev's Inequality Outlier Clipping Envelope
                # [-k_clip, +k_clip] where k_clip = sqrt(1 / P_tail) approx 31.62
                z_clipped = np.clip(z, -k_clip, k_clip)
                scaled_matrix[:, idx] = z_clipped

            return scaled_matrix
        else:
            # Fallback to standard Z-Score scaler (supports existing serialized model artifacts)
            scaler = getattr(self, "scaler", getattr(self, "standard_scaler", None))
            if scaler is not None:
                return scaler.transform(aligned_features[self.feature_columns])
            raise RuntimeError("No valid scaler found in preprocessor artifact.")

    def fit_transform(self, X: pd.DataFrame) -> np.ndarray:
        """Fit parameters and transform training data in a single call."""
        return self.fit(X).transform(X)

    def _align_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Ensure all required feature columns exist and infinite values are replaced with NaN."""
        present_cols = [c for c in self.feature_columns if c in df.columns]
        aligned = df[present_cols].apply(pd.to_numeric, errors="coerce")
        missing_cols = [c for c in self.feature_columns if c not in df.columns]
        for col in missing_cols:
            aligned[col] = 0.0
        return aligned[self.feature_columns].replace([np.inf, -np.inf], np.nan)


def load_ciciot_directory(
    root: Path,
    sample_size: Optional[int] = None
) -> Tuple[pd.DataFrame, pd.Series]:
    """Load balanced benign and attack flows directly from raw CIC-IoT category folders."""
    benign_dir = root / "Benign_Final"
    attack_dirs = sorted([d for d in root.iterdir() if d.is_dir() and d.name != "Benign_Final"])

    total_target = sample_size or 50000
    benign_target = total_target // 2
    attack_total = total_target - benign_target
    per_attack = max(10, attack_total // len(attack_dirs)) if attack_dirs else 0

    print(f"[*] Loading new dataset directly from: {root} ({len(attack_dirs)} attack types found)")
    print(f"[*] Target sample size: {total_target:,} flows ({benign_target:,} benign, {attack_total:,} attacks across {len(attack_dirs)} types)")

    benign_csvs = list(benign_dir.glob("*.csv"))
    if not benign_csvs:
        raise FileNotFoundError(f"No CSV found in benign directory: {benign_dir}")
    df_benign = pd.read_csv(benign_csvs[0], nrows=benign_target, low_memory=False)
    df_benign["label"] = "BenignTraffic"

    attack_dfs = []
    for ad in attack_dirs:
        csv_files = list(ad.glob("*.csv"))
        if csv_files:
            try:
                adf = pd.read_csv(csv_files[0], nrows=per_attack, low_memory=False)
                adf["label"] = ad.name
                attack_dfs.append(adf)
            except Exception:
                pass

    df_combined = pd.concat([df_benign] + attack_dfs, ignore_index=True)
    df_combined = df_combined.sample(frac=1.0, random_state=42).reset_index(drop=True)
    df_combined = clean_dataframe(df_combined)

    y = encode_labels(df_combined["label"])
    X = df_combined.drop(columns=["label"])

    normal_count = int((y == 0).sum())
    abnormal_count = int((y == 1).sum())
    total = len(y)
    print(
        f"[+] Successfully loaded {total:,} traffic records | "
        f"Normal: {normal_count:,} ({normal_count / total * 100:.1f}%) | "
        f"Abnormal: {abnormal_count:,} ({abnormal_count / total * 100:.1f}%) across {len(attack_dfs)} attack categories"
    )
    return X, y


def load_dataset(
    file_path: Union[str, Path],
    sample_size: Optional[int] = None
) -> Tuple[pd.DataFrame, pd.Series]:
    """Load and prepare a dataset CSV file or directory, separating features (X) and binary label (y)."""
    raw_str = str(file_path).strip()

    if (raw_str.startswith("data/") or raw_str.startswith("data\\")) and (":\\" in raw_str or ":/" in raw_str):
        fixed_path_str = raw_str[5:]
        if Path(fixed_path_str).exists():
            file_path = Path(fixed_path_str)
        else:
            file_path = Path(raw_str)
    else:
        file_path = Path(raw_str)

    if not file_path.exists():
        raise FileNotFoundError(f"Dataset file not found at: {file_path}")

    if file_path.is_dir():
        ciciot_root = file_path / "CSV" if (file_path / "CSV" / "Benign_Final").exists() else file_path
        if (ciciot_root / "Benign_Final").exists():
            return load_ciciot_directory(ciciot_root, sample_size=sample_size)

        csv_files = list(file_path.glob("*.csv"))
        if not csv_files:
            csv_files = list(file_path.rglob("*.csv"))
        if csv_files:
            file_path = csv_files[0]
            print(f"[*] Directory specified. Found CSV file: {file_path}")
        else:
            raise ValueError(f"No CSV files found in directory: {file_path}")

    print(f"[*] Reading dataset from: {file_path}")
    df = pd.read_csv(file_path, low_memory=False)
    df = clean_dataframe(df)

    if sample_size and len(df) > sample_size:
        print(f"[*] Subsampling dataset to {sample_size:,} records for fast experimentation...")
        df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)

    target_col = None
    for col in df.columns:
        if col.lower() == TARGET_COLUMN.lower():
            target_col = col
            break

    if target_col is None:
        raise ValueError(
            f"Target column '{TARGET_COLUMN}' not found in dataset. Columns present: {list(df.columns)}"
        )

    y = encode_labels(df[target_col])
    X = df.drop(columns=[target_col])

    normal_count = int((y == 0).sum())
    abnormal_count = int((y == 1).sum())
    total = len(y)
    print(
        f"[+] Loaded {total:,} traffic records | "
        f"Normal: {normal_count:,} ({normal_count / total * 100:.1f}%) | "
        f"Abnormal: {abnormal_count:,} ({abnormal_count / total * 100:.1f}%)"
    )

    return X, y


def prepare_train_test_data(
    file_path: Union[str, Path],
    test_size: float = 0.2,
    sample_size: Optional[int] = None,
    random_state: int = 42,
    scaling_method: str = "robust_mad",
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, IoTDataPreprocessor]:
    """Full pipeline: load, clean, encode labels, train/test split, and robust scale."""
    X, y = load_dataset(file_path, sample_size=sample_size)

    # Stratified split to preserve class proportions
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    preprocessor = IoTDataPreprocessor(method=scaling_method)
    X_train_scaled = preprocessor.fit_transform(X_train)
    X_test_scaled = preprocessor.transform(X_test)

    return (
        X_train_scaled,
        X_test_scaled,
        y_train.to_numpy(),
        y_test.to_numpy(),
        preprocessor
    )
