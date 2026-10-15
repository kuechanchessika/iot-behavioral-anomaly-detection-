"""Data preprocessing and feature pipeline for IoT traffic analysis."""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from src.config import BENIGN_LABELS, CICIOT2023_FEATURES, TARGET_COLUMN


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Clean column names and handle infinite or missing numeric values."""
    df = df.copy()
    df.columns = df.columns.str.strip()
    return df



def encode_labels(labels: pd.Series) -> pd.Series:
    """Convert raw labels into binary format: 0 for Normal (Benign), 1 for Abnormal (Attack)."""
    cleaned_labels = labels.astype(str).str.strip().str.lower()
    # Map benign labels to 0, all other traffic (attacks) to 1
    is_benign = cleaned_labels.isin(BENIGN_LABELS)
    binary_labels = np.where(is_benign, 0, 1)
    return pd.Series(binary_labels, index=labels.index, name="is_abnormal")


class IoTDataPreprocessor:
    """Pipeline to preprocess, scale, and align IoT network traffic features."""

    def __init__(self, feature_columns: Optional[List[str]] = None):
        self.feature_columns = feature_columns or CICIOT2023_FEATURES
        self.scaler = StandardScaler()
        self.impute_values: Dict[str, float] = {}
        self.is_fitted = False

    def fit(self, X: pd.DataFrame) -> "IoTDataPreprocessor":
        """Compute imputation values and scaling parameters from training data."""
        X_clean = clean_dataframe(X)
        aligned_features = self._align_features(X_clean)

        # Compute median imputation values for numeric columns
        for col in self.feature_columns:
            median_val = float(aligned_features[col].median(skipna=True))
            if np.isnan(median_val):
                median_val = 0.0
            self.impute_values[col] = median_val
            aligned_features[col] = aligned_features[col].fillna(median_val)

        # Fit the standard scaler
        self.scaler.fit(aligned_features[self.feature_columns])
        self.is_fitted = True
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Apply feature alignment, imputation, and scaling."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before calling transform.")

        X_clean = clean_dataframe(X)
        aligned_features = self._align_features(X_clean)

        # Impute missing values using stored training medians
        for col in self.feature_columns:
            aligned_features[col] = aligned_features[col].fillna(self.impute_values.get(col, 0.0))

        return self.scaler.transform(aligned_features[self.feature_columns])

    def fit_transform(self, X: pd.DataFrame) -> np.ndarray:
        """Fit and transform in a single call."""
        return self.fit(X).transform(X)

    def _align_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Ensure all required feature columns exist and are numeric."""
        present_cols = [c for c in self.feature_columns if c in df.columns]
        aligned = df[present_cols].apply(pd.to_numeric, errors="coerce")
        missing_cols = [c for c in self.feature_columns if c not in df.columns]
        for col in missing_cols:
            aligned[col] = 0.0
        return aligned[self.feature_columns].replace([np.inf, -np.inf], np.nan)



def load_dataset(
    file_path: Union[str, Path],
    sample_size: Optional[int] = None
) -> Tuple[pd.DataFrame, pd.Series]:
    """Load and prepare a dataset CSV file, separating features (X) and binary label (y)."""
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Dataset file not found at: {file_path}")

    print(f"[*] Reading dataset from: {file_path}")
    df = pd.read_csv(file_path, low_memory=False)
    df = clean_dataframe(df)

    if sample_size and len(df) > sample_size:
        print(f"[*] Subsampling dataset to {sample_size:,} records for fast experimentation...")
        df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)

    # Check for target column
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
    random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, IoTDataPreprocessor]:
    """Full pipeline: load, clean, encode labels, train/test split, and scale."""
    X, y = load_dataset(file_path, sample_size=sample_size)

    # Stratified train/test split to preserve attack-to-normal ratio
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    preprocessor = IoTDataPreprocessor()
    X_train_scaled = preprocessor.fit_transform(X_train)
    X_test_scaled = preprocessor.transform(X_test)

    return (
        X_train_scaled,
        X_test_scaled,
        y_train.to_numpy(),
        y_test.to_numpy(),
        preprocessor
    )
