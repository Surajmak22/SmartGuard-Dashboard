import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from typing import Dict, Any
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Machine Learning Engine for Network Anomaly Detection.
    Uses Random Forest trained on NSL-KDD dataset.
    """
    
    def __init__(self, model_path="data/models/nsl_kdd_rf.joblib", data_path="data/training/nsl_kdd_mini.csv"):
        self.model_path = model_path
        self.data_path = data_path
        self.model = None
        self.encoders = {}
        self.scaler = None
        self.required_columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes'
            # We simplify input features for real-time inference match
        ]
        
        # Ensure model directory exists
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        self._load_or_train()

    def _load_or_train(self):
        """Load existing model or train a new one."""
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                self.model = data['model']
                self.encoders = data['encoders']
                self.scaler = data['scaler']
                logger.info("Loaded existing ML model.")
            except Exception as e:
                logger.error(f"Error loading model: {e}")
                self.train()
        else:
            logger.info("No model found. Training new model...")
            self.train()

    def train(self):
        """Train the model on local NSL-KDD subset."""
        try:
            if not os.path.exists(self.data_path):
                logger.error(f"Training data not found at {self.data_path}")
                return

            df = pd.read_csv(self.data_path)
            
            # Preprocessing
            # 1. Encode Categoricals
            categorical_cols = ['protocol_type', 'service', 'flag', 'class']
            
            for col in categorical_cols:
                if col in df.columns:
                    le = LabelEncoder()
                    df[col] = le.fit_transform(df[col].astype(str))
                    self.encoders[col] = le
            
            # 2. Features & Target
            X = df.drop(['class'], axis=1, errors='ignore')
            y = df['class'] if 'class' in df.columns else np.zeros(len(df))
            
            # 3. Scale
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            
            # 4. Train
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.model.fit(X_scaled, y)
            
            # 5. Save
            joblib.dump({
                'model': self.model,
                'encoders': self.encoders,
                'scaler': self.scaler,
                'columns': X.columns.tolist() # Save expected columns
            }, self.model_path)
            
            logger.info("Model training complete and saved.")
            
        except Exception as e:
            logger.error(f"Training failed: {e}")

    def predict(self, packet_info: Dict[str, Any]) -> float:
        """
        Predict probability of anomaly for a single packet.
        Returns: 0.0 (Normal) to 1.0 (Anomaly)
        """
        if not self.model:
            return 0.0
            
        try:
            # Map packet features to NSL-KDD structure
            # This is a critical simplification step
            features = {
                'duration': 0,
                'protocol_type': str(packet_info.get('protocol', 'TCP')).lower(),
                'service': self._map_port_to_service(packet_info.get('dport', 80)),
                'flag': 'SF', # Assume standard flag for now
                'src_bytes': packet_info.get('length', 0),
                'dst_bytes': 0,
                # Fill rest with defaults (zeros)
            }
            
            # Create full feature vector based on training columns
            # We load the columns from training time
            saved_data = joblib.load(self.model_path)
            expected_cols = saved_data['columns']
            
            input_vector = []
            for col in expected_cols:
                val = features.get(col, 0)
                
                # Encode if necessary
                if col in self.encoders:
                    try:
                        val = self.encoders[col].transform([str(val)])[0]
                    except:
                        val = 0 # Unknown category
                
                input_vector.append(val)
            
            # Scale
            input_scaled = self.scaler.transform([input_vector])
            
            # Predict
            # Determine which class index corresponds to 'anomaly'
            # In our CSV: normal=1, anomaly=0 (based on LabelEncoder sort order: 'anomaly' < 'normal')
            # Wait, let's check: 'anomaly', 'normal'. Sorted: idx 0=anomaly, idx 1=normal.
            
            probs = self.model.predict_proba(input_scaled)[0]
            
            # If classes are ['anomaly', 'normal'], then probs[0] is anomaly probability
            # We need to be careful. Let's assume 'anomaly' is index 0.
            if 'class' in self.encoders:
                 classes = self.encoders['class'].classes_
                 anomaly_idx = np.where(classes == 'anomaly')[0][0]
                 return float(probs[anomaly_idx])
            
            return float(probs[0]) # Fallback
            
        except Exception as e:
            # logger.error(f"Prediction error: {e}")
            return 0.0

    def _map_port_to_service(self, port):
        """Map common ports to NSL-KDD service names."""
        mapping = {
            80: 'http', 443: 'http', 8080: 'http',
            21: 'ftp', 20: 'ftp_data',
            22: 'ssh', 23: 'telnet',
            25: 'smtp',
            53: 'dns',
            110: 'pop_3', 995: 'pop_3',
            143: 'imap4', 993: 'imap4'
        }
        return mapping.get(port, 'other')

# Singleton
ml_engine = AnomalyDetector()
