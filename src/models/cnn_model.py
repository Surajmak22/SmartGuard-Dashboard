import numpy as np
from sklearn.neural_network import MLPClassifier

class NeuralClassifierSklearn:
    """
    MLP Classifier for pattern recognition in network traffic.
    Robust alternative to CNN for environments without GPU/TensorFlow.
    """
    def __init__(self, hidden_layer_sizes=(64, 32)):
        self.model = MLPClassifier(
            hidden_layer_sizes=hidden_layer_sizes,
            activation='relu',
            solver='adam',
            random_state=42,
            max_iter=200
        )

    def fit(self, X, y):
        self.model.fit(X, y)

    def predict(self, X):
        # Handle 3D inputs if they were prepared for CNN
        if len(X.shape) == 3:
            X = X.reshape(X.shape[0], -1)
        return self.model.predict_proba(X)[:, 1].reshape(-1, 1)

    def save(self, path):
        import joblib
        joblib.dump(self.model, f"{path}_mlp.joblib")
