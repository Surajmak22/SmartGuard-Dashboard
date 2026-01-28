import numpy as np
from typing import Dict, Any, List
import joblib

class HybridThreatDetector:
    """
    Hybrid Ensemble for Network Threat Detection.
    Combines Anomaly Detection, Random Forest, and Neural Pattern Recognition.
    """
    def __init__(self, rf_model: Any, pattern_model: Any, anomaly_model: Any):
        self.rf_model = rf_model
        self.pattern_model = pattern_model
        self.anomaly_model = anomaly_model
        
        # Initial weights
        self.weights = {
            'rf': 0.4,
            'pattern': 0.4,
            'anomaly': 0.2
        }
        
    def predict(self, X: np.ndarray) -> Dict[str, Any]:
        """
        Produce individual and ensemble predictions.
        """
        # 1. Random Forest prediction
        rf_proba = self.rf_model.predict_proba(X)[:, 1]
        
        # 2. Pattern (MLP) prediction
        pattern_proba = self.pattern_model.predict(X).flatten()
        
        # 3. Anomaly scores
        ae_scores = self.anomaly_model.get_reconstruction_error(X)
        
        # Weighted Ensemble Voting
        final_scores = (
            self.weights['rf'] * rf_proba +
            self.weights['pattern'] * pattern_proba +
            self.weights['anomaly'] * ae_scores
        )
        
        # Final prediction label
        final_labels = (final_scores > 0.5).astype(int)
        
        return {
            'final_prediction': final_labels.tolist(),
            'final_score': final_scores.tolist(),
            'rf_contribution': (self.weights['rf'] * rf_proba).tolist(),
            'cnn_contribution': (self.weights['pattern'] * pattern_proba).tolist(),
            'ae_contribution': (self.weights['anomaly'] * ae_scores).tolist(),
            'confidence': np.clip(np.abs(final_scores - 0.5) * 2, 0, 1).tolist()
        }

    def tune_weights(self, metrics: Dict[str, float]):
        total_score = sum(metrics.values())
        if total_score > 0:
            for key in self.weights.keys():
                metric_key = f"{key}_f1"
                if metric_key in metrics:
                    self.weights[key] = metrics[metric_key] / total_score
        
    def save(self, path: str):
        joblib.dump({
            'weights': self.weights,
            'rf_model': self.rf_model,
            'pattern_model': self.pattern_model,
            'anomaly_model': self.anomaly_model
        }, f"{path}_hybrid_ensemble.joblib")
