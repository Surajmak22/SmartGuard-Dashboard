import numpy as np
from sklearn.ensemble import IsolationForest

class AnomalyDetectorSklearn:
    """
    Isolation Forest for detecting anomalies in network traffic.
    Robust alternative to Autoencoder for low-latency production environments.
    """
    def __init__(self, contamination: float = 0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.threshold = 0.5 # Dummy to keep interface consistent

    def fit(self, X):
        self.model.fit(X)

    def is_anomaly(self, X):
        """Returns binary labels (1 for anomaly, 0 for normal)."""
        preds = self.model.predict(X)
        return (preds == -1).astype(int)

    def get_reconstruction_error(self, X):
        """Returns the anomaly score (lower is more abnormal). 
        We invert it so higher is more abnormal for the ensemble logic."""
        scores = self.model.decision_function(X) # Higher = more normal
        # Normalize to 0-1 where 1 is more abnormal
        min_score = np.min(scores) if len(scores) > 0 else 0
        max_score = np.max(scores) if len(scores) > 0 else 1
        if max_score == min_score:
            return np.zeros_like(scores)
        return (max_score - scores) / (max_score - min_score)

    def save(self, path):
        import joblib
        joblib.dump(self.model, f"{path}_iforest.joblib")
