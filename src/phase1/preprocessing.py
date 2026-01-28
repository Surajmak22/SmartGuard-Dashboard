from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


@dataclass(frozen=True)
class PreparedData:
    X: pd.DataFrame
    y: pd.Series
    feature_columns: List[str]


def _normalize_label_value(v: object) -> str:
    s = str(v).strip().lower()
    if s in {"benign", "normal", "0", "false"}:
        return "BENIGN"
    if s in {"attack", "malicious", "1", "true", "anomaly"}:
        return "ATTACK"
    # Keep original label value (multiclass datasets) but normalize casing
    return str(v).strip()


def prepare_xy(
    df: pd.DataFrame,
    *,
    label_col: str,
    drop_cols: Optional[Sequence[str]] = None,
    binary: bool = True,
) -> PreparedData:
    """Split a dataframe into features/labels.

    Academic assumption:
    - For cross-dataset evaluation, we default to binary classification (BENIGN vs ATTACK)
      to keep label spaces compatible between UNSW-NB15 and CICIDS2017.
    """
    if label_col not in df.columns:
        raise ValueError(f"Label column '{label_col}' not found. Available columns: {list(df.columns)[:20]}")

    drop_cols_set = {label_col}
    if drop_cols:
        drop_cols_set |= set(drop_cols)

    y_raw = df[label_col]
    if binary:
        y = y_raw.map(_normalize_label_value)
        # anything not BENIGN is treated as ATTACK (simple academic assumption)
        y = y.where(y == "BENIGN", "ATTACK")
    else:
        y = y_raw.astype(str)

    X = df.drop(columns=list(drop_cols_set), errors="ignore")

    # Drop constant columns to reduce noise
    nunique = X.nunique(dropna=False)
    constant_cols = nunique[nunique <= 1].index.tolist()
    if constant_cols:
        X = X.drop(columns=constant_cols, errors="ignore")

    return PreparedData(X=X, y=y, feature_columns=list(X.columns))


class CleanInfValues(BaseEstimator, TransformerMixin):
    """Replace inf and large values with NaN so they can be imputed."""
    
    def __init__(self, max_abs_value=1e10):
        self.max_abs_value = max_abs_value
        
    def fit(self, X, y=None):
        return self
        
    def transform(self, X):
        if isinstance(X, pd.DataFrame):
            X = X.copy()
            # Replace inf/-inf with NaN
            X = X.replace([np.inf, -np.inf], np.nan)
            # Cap extremely large values
            X = X.clip(-self.max_abs_value, self.max_abs_value, axis=1)
            return X
        else:  # numpy array
            X = X.copy()
            X[~np.isfinite(X)] = np.nan
            X = np.clip(X, -self.max_abs_value, self.max_abs_value)
            return X

    def get_feature_names_out(self, input_features=None):
        if input_features is None:
            return np.array([], dtype=object)
        return np.asarray(input_features, dtype=object)


def build_preprocessor(X: pd.DataFrame) -> ColumnTransformer:
    """Create a preprocessing transformer: clean -> impute -> one-hot encode -> scale."""
    cat_cols = X.select_dtypes(include=["object", "category", "bool"]).columns.tolist()
    num_cols = [c for c in X.columns if c not in cat_cols]

    numeric_pipe = Pipeline(
        steps=[
            ("cleaner", CleanInfValues(max_abs_value=1e10)),  # Clean before imputation
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )

    categorical_pipe = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ]
    )

    return ColumnTransformer(
        transformers=[
            ("num", numeric_pipe, num_cols),
            ("cat", categorical_pipe, cat_cols),
        ],
        remainder="drop",
        verbose_feature_names_out=False,
    )


def get_feature_names(preprocessor: ColumnTransformer) -> List[str]:
    """Get output feature names after preprocessing."""
    if hasattr(preprocessor, "get_feature_names_out"):
        return [str(x) for x in preprocessor.get_feature_names_out()]
    return []
