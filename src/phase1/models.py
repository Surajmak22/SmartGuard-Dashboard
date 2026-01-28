from __future__ import annotations

from typing import Any

from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC


SUPPORTED_MODELS = (
    "random_forest",
    "svm",
)


def build_model(model_name: str) -> Any:
    name = model_name.strip().lower()

    if name in {"rf", "random_forest", "randomforest"}:
        return RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced",
        )

    if name in {"svm", "svc"}:
        return SVC(
            kernel="rbf",
            probability=True,
            class_weight="balanced",
            random_state=42,
        )

    raise ValueError(f"Unsupported model '{model_name}'. Supported: {SUPPORTED_MODELS}")
