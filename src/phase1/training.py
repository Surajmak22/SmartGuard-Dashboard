from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split

from .metrics import classification_metrics
from .models import build_model
from .preprocessing import build_preprocessor, get_feature_names, prepare_xy
from .resampling import smote_resample


@dataclass(frozen=True)
class TrainedBundle:
    """A lightweight container for Phase-1 models.

    This is intentionally simple for academic demonstration and Streamlit Cloud.
    """

    model_name: str
    preprocessor: Any
    model: Any
    feature_names: List[str]
    label_positive: str
    X_train_sample: Optional[pd.DataFrame] = None


def train_binary_classifier(
    df: pd.DataFrame,
    *,
    label_col: str,
    model_name: str,
    drop_cols: Optional[Sequence[str]] = None,
    test_size: float = 0.2,
    random_state: int = 42,
    use_smote: bool = True,
) -> Tuple[TrainedBundle, Dict[str, float], pd.DataFrame]:
    """Train a binary classifier (BENIGN vs ATTACK) and return evaluation artifacts.

    Returns:
        - TrainedBundle (preprocessor + model)
        - metrics dict (accuracy/precision/recall/f1/roc_auc)
        - predictions dataframe for the test split (y_true, y_pred, y_score)

    Academic assumption:
    - Any non-BENIGN label is treated as ATTACK to keep datasets compatible.
    """

    prepared = prepare_xy(df, label_col=label_col, drop_cols=drop_cols, binary=True)

    X_train, X_test, y_train, y_test = train_test_split(
        prepared.X,
        prepared.y,
        test_size=test_size,
        random_state=random_state,
        stratify=prepared.y,
    )

    y_train_bin = (y_train != "BENIGN").astype(int).to_numpy()
    y_test_bin = (y_test != "BENIGN").astype(int).to_numpy()

    preprocessor = build_preprocessor(X_train)
    X_train_t = preprocessor.fit_transform(X_train)
    X_test_t = preprocessor.transform(X_test)

    if use_smote:
        # SMOTE after preprocessing (feature space). This is a common simple approach.
        X_train_t, y_train_bin = smote_resample(X_train_t, y_train_bin, random_state=random_state)

    model = build_model(model_name)
    model.fit(X_train_t, y_train_bin)

    y_pred = model.predict(X_test_t)

    y_score = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X_test_t)
        if proba.shape[1] >= 2:
            y_score = proba[:, 1]

    metrics = classification_metrics(y_test_bin, y_pred, y_score=y_score, average="binary")

    pred_df = pd.DataFrame(
        {
            "y_true": y_test_bin,
            "y_pred": y_pred,
            "y_score": y_score if y_score is not None else np.nan,
        }
    )

    # Save a sample of training data for SHAP background
    # X_train_t is numpy, convert to DF with names for better usability
    feature_names = get_feature_names(preprocessor)
    X_train_sample_df = pd.DataFrame(X_train_t, columns=feature_names).sample(
        n=min(100, len(X_train_t)), random_state=42
    )

    bundle = TrainedBundle(
        model_name=model_name,
        preprocessor=preprocessor,
        model=model,
        feature_names=feature_names,
        label_positive="ATTACK",
        X_train_sample=X_train_sample_df,
    )

    return bundle, metrics, pred_df


def transform_features(bundle: TrainedBundle, X: pd.DataFrame) -> np.ndarray:
    """Transform raw feature dataframe into model-ready numpy array."""
    return bundle.preprocessor.transform(X)
