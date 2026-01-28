from __future__ import annotations

from dataclasses import dataclass
from collections import deque
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class PredictionResult:
    y_pred: np.ndarray
    confidence: np.ndarray
    severity: np.ndarray
    low_confidence: np.ndarray
    proba: Optional[np.ndarray]


class Predictor:
    """Batch + streaming-friendly predictor with confidence thresholding and simple FP reduction.

    Notes (academic Phase-1 assumptions):
    - Confidence is taken as max class probability (when available).
    - If a model does not support probabilities, we fall back to a score-derived confidence.
    - "Normal" class detection uses a configurable set of label names.
    """

    def __init__(
        self,
        model: Any,
        *,
        confidence_threshold: float = 0.7,
        normal_class_names: Sequence[str] = ("normal", "benign"),
        per_class_thresholds: Optional[Mapping[Union[int, str], float]] = None,
        smoothing_window: int = 0,
    ) -> None:
        self.model = model
        self.confidence_threshold = float(confidence_threshold)
        self.normal_class_names = tuple(str(x).lower() for x in normal_class_names)
        self.per_class_thresholds: Dict[Union[int, str], float] = dict(per_class_thresholds or {})

        self.smoothing_window = int(smoothing_window)
        self._score_history: Deque[float] = deque(maxlen=max(self.smoothing_window, 1))

    def _get_classes(self) -> Optional[np.ndarray]:
        return getattr(self.model, "classes_", None)

    def _predict_proba(self, X: pd.DataFrame) -> Optional[np.ndarray]:
        if hasattr(self.model, "predict_proba"):
            return self.model.predict_proba(X)
        return None

    def _decision_scores(self, X: pd.DataFrame) -> Optional[np.ndarray]:
        # Used only as a fallback when probabilities are unavailable.
        if hasattr(self.model, "decision_function"):
            scores = self.model.decision_function(X)
            scores_arr = np.asarray(scores)
            if scores_arr.ndim == 1:
                return scores_arr
            # For multiclass, decision_function returns shape (n_samples, n_classes)
            return scores_arr.max(axis=1)
        return None

    @staticmethod
    def _softmax(z: np.ndarray) -> np.ndarray:
        z = z - np.max(z)
        exp = np.exp(z)
        return exp / (np.sum(exp) + 1e-12)

    def _fallback_confidence(self, scores_1d: np.ndarray) -> np.ndarray:
        # Map arbitrary scores to (0, 1) with a logistic transform.
        return 1.0 / (1.0 + np.exp(-scores_1d))

    def _is_normal_label(self, label: Union[int, str]) -> bool:
        return str(label).lower() in self.normal_class_names

    def _apply_per_class_thresholding(
        self,
        classes: Optional[np.ndarray],
        y_pred: np.ndarray,
        conf: np.ndarray,
        proba: Optional[np.ndarray],
    ) -> Tuple[np.ndarray, np.ndarray]:
        if not self.per_class_thresholds:
            return y_pred, conf

        if proba is None or classes is None:
            return y_pred, conf

        classes_list = list(classes)
        normal_idx = None
        for i, c in enumerate(classes_list):
            if self._is_normal_label(c):
                normal_idx = i
                break

        # If we cannot identify normal class index, skip thresholding.
        if normal_idx is None:
            return y_pred, conf

        y_adj = y_pred.copy()
        conf_adj = conf.copy()

        for i in range(len(y_adj)):
            pred_label = y_adj[i]
            try:
                pred_idx = classes_list.index(pred_label)
            except ValueError:
                continue

            threshold = self.per_class_thresholds.get(pred_label)
            if threshold is None:
                continue

            pred_prob = float(proba[i, pred_idx])
            if pred_prob < float(threshold):
                # Downgrade to normal class to reduce false positives.
                y_adj[i] = classes_list[normal_idx]
                conf_adj[i] = float(proba[i, normal_idx])

        return y_adj, conf_adj

    def _apply_smoothing(self, conf: np.ndarray) -> np.ndarray:
        if self.smoothing_window <= 1:
            return conf

        smoothed = np.empty_like(conf, dtype=float)
        for i, val in enumerate(conf):
            self._score_history.append(float(val))
            smoothed[i] = float(np.mean(self._score_history))
        return smoothed

    def _severity(self, y_pred: np.ndarray, confidence: np.ndarray) -> np.ndarray:
        sev = np.empty(len(y_pred), dtype=object)
        for i, (lbl, c) in enumerate(zip(y_pred, confidence)):
            if self._is_normal_label(lbl):
                sev[i] = "Low"
                continue

            if c >= 0.9:
                sev[i] = "High"
            elif c >= 0.7:
                sev[i] = "Medium"
            else:
                sev[i] = "Low"
        return sev

    def predict(self, X: pd.DataFrame) -> PredictionResult:
        """Predict labels with confidence + severity.

        Returns:
            PredictionResult containing predicted labels, confidence score, severity,
            and whether prediction is low-confidence.
        """
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)

        proba = self._predict_proba(X)
        classes = self._get_classes()

        if proba is not None:
            y_pred = self.model.predict(X)
            conf = np.max(proba, axis=1)
        else:
            y_pred = self.model.predict(X)
            scores = self._decision_scores(X)
            if scores is None:
                # Worst-case fallback: no scores/proba => treat as fully confident.
                conf = np.ones(len(y_pred), dtype=float)
            else:
                conf = self._fallback_confidence(np.asarray(scores, dtype=float))

        y_pred, conf = self._apply_per_class_thresholding(classes, np.asarray(y_pred), np.asarray(conf), proba)
        conf = self._apply_smoothing(conf)

        low_conf = conf < self.confidence_threshold
        severity = self._severity(y_pred, conf)

        return PredictionResult(
            y_pred=np.asarray(y_pred),
            confidence=np.asarray(conf, dtype=float),
            severity=np.asarray(severity),
            low_confidence=np.asarray(low_conf, dtype=bool),
            proba=proba,
        )
