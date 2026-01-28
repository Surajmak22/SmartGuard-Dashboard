import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from typing import Dict, Any, Optional, Tuple
import joblib
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    A class for detecting anomalies in network traffic using Isolation Forest.
    """
    
    def __init__(self, model_params: Dict[str, Any] = None):
        """
        Initialize the AnomalyDetector.
        
        Args:
            model_params: Dictionary of parameters for the Isolation Forest model
        """
        # Default parameters
        default_params = {
            'n_estimators': 100,
            'max_samples': 'auto',
            'contamination': 0.1,
            'max_features': 1.0,
            'bootstrap': False,
            'n_jobs': -1,
            'random_state': 42,
            'verbose': 0
        }
        
        # Update with provided parameters
        if model_params:
            default_params.update(model_params)
        
        # Create the model pipeline
        self.model = Pipeline([
            ('scaler', StandardScaler()),
            ('isolation_forest', IsolationForest(**default_params))
        ])
        
        # Store training metrics
        self.training_metrics = {}
        
    def preprocess_data(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Preprocess the input data for the model.
        
        Args:
            X: Input features DataFrame
            
        Returns:
            Preprocessed DataFrame
        """
        # Make a copy to avoid modifying the original
        X_processed = X.copy()
        
        # Convert boolean columns to int
        for col in X_processed.select_dtypes(include=['bool']).columns:
            X_processed[col] = X_processed[col].astype(int)
        
        # Fill any remaining NaNs with 0
        X_processed = X_processed.fillna(0)
        
        return X_processed
    
    def train(self, X: pd.DataFrame) -> Dict[str, Any]:
        """
        Train the anomaly detection model.
        
        Args:
            X: Training data features
            
        Returns:
            Dictionary containing training metrics
        """
        try:
            # Preprocess the data
            X_processed = self.preprocess_data(X)
            
            # Train the model
            self.model.fit(X_processed)
            
            # Calculate training metrics
            train_scores = self.model.decision_function(X_processed)
            
            # Store metrics
            self.training_metrics = {
                'n_samples': len(X_processed),
                'n_features': X_processed.shape[1],
                'anomaly_ratio': np.mean(self.model.predict(X_processed) == -1),
                'avg_anomaly_score': np.mean(train_scores),
                'min_anomaly_score': np.min(train_scores),
                'max_anomaly_score': np.max(train_scores)
            }
            
            logger.info(f"Model trained successfully on {len(X_processed)} samples")
            logger.info(f"Training anomaly ratio: {self.training_metrics['anomaly_ratio']:.2f}")
            
            return self.training_metrics
            
        except Exception as e:
            logger.error(f"Error during model training: {str(e)}")
            raise
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict anomalies in the input data.
        
        Args:
            X: Input features DataFrame
            
        Returns:
            Array of predictions (-1 for anomalies, 1 for normal)
        """
        try:
            X_processed = self.preprocess_data(X)
            return self.model.predict(X_processed)
        except Exception as e:
            logger.error(f"Error during prediction: {str(e)}")
            raise
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict anomaly scores for the input data.
        
        Args:
            X: Input features DataFrame
            
        Returns:
            Array of anomaly scores (lower values indicate higher anomaly likelihood)
        """
        try:
            X_processed = self.preprocess_data(X)
            return self.model.decision_function(X_processed)
        except Exception as e:
            logger.error(f"Error during probability prediction: {str(e)}")
            raise
    
    def evaluate(self, X: pd.DataFrame, y: np.ndarray = None, threshold: float = None) -> Dict[str, Any]:
        """
        Evaluate the model on test data.
        
        Args:
            X: Test data features
            y: True labels (1 for anomaly, 0 for normal)
            threshold: Decision threshold for anomaly detection
            
        Returns:
            Dictionary containing evaluation metrics
        """
        try:
            # Get anomaly scores
            scores = self.predict_proba(X)
            
            # If threshold is not provided, use the one that maximizes F1 score
            if y is not None and threshold is None:
                from sklearn.metrics import precision_recall_curve, f1_score
                
                # Invert scores since we want lower scores to indicate anomalies
                precision, recall, thresholds = precision_recall_curve(
                    y, -scores, pos_label=1
                )
                
                # Calculate F1 score for each threshold
                f1_scores = 2 * (precision * recall) / (precision + recall + 1e-10)
                best_idx = np.argmax(f1_scores)
                threshold = -thresholds[best_idx]  # Convert back to original scale
                
                # Calculate metrics at optimal threshold
                y_pred = (scores < threshold).astype(int)
                f1 = f1_score(y, y_pred)
                precision = precision[best_idx]
                recall = recall[best_idx]
                
                metrics = {
                    'threshold': threshold,
                    'f1_score': f1,
                    'precision': precision,
                    'recall': recall,
                    'roc_auc': None,  # Can be added if needed
                    'confusion_matrix': None  # Can be added if needed
                }
                
                return metrics
            
            # If no labels are provided, just return the scores
            return {'scores': scores}
            
        except Exception as e:
            logger.error(f"Error during evaluation: {str(e)}")
            raise
    
    def save_model(self, filepath: str):
        """
        Save the trained model to disk.
        
        Args:
            filepath: Path to save the model
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # Save the model
            joblib.dump(self.model, filepath)
            logger.info(f"Model saved to {filepath}")
            
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
            raise
    
    @classmethod
    def load_model(cls, filepath: str) -> 'AnomalyDetector':
        """
        Load a trained model from disk.
        
        Args:
            filepath: Path to the saved model
            
        Returns:
            Loaded AnomalyDetector instance
        """
        try:
            # Create a new instance
            detector = cls()
            
            # Load the model
            detector.model = joblib.load(filepath)
            logger.info(f"Model loaded from {filepath}")
            
            return detector
            
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise
