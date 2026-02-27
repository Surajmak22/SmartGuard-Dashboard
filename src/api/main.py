from fastapi import FastAPI, HTTPException, BackgroundTasks, File, Form
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
import time
import numpy as np
import pandas as pd
import uuid
from ..models.hybrid_ensemble import HybridThreatDetector
from ..logging.structured_logger import StructuredLogger
from ..scanner.engine import MalwareEngine
from ..utils.history_manager import HistoryManager

app = FastAPI(title="SmartGuard AI - Enterprise SOC Platform")
logger = StructuredLogger()
history = HistoryManager()

# Global state
detector: Optional[HybridThreatDetector] = None
malware_engine: Optional[MalwareEngine] = None

class PredictionRequest(BaseModel):
    features: List[float]
    source_ip: str

class PredictionResponse(BaseModel):
    prediction: str
    threat_score: float
    severity: str
    confidence: float
    contributions: Dict[str, float]
    latency_ms: float

@app.on_event("startup")
async def startup_event():
    # Initialize engines on startup
    await initialize_models()

@app.post("/initialize")
async def initialize_models():
    global detector, malware_engine
    try:
        input_dim = 20
        from sklearn.ensemble import RandomForestClassifier
        from ..models.cnn_model import NeuralClassifierSklearn
        from ..models.autoencoder import AnomalyDetectorSklearn
        
        # Initialize Hybrid Ensemble for Network Detection
        rf = RandomForestClassifier(n_estimators=10)
        rf.fit(np.random.rand(10, input_dim), np.random.randint(0, 2, 10))
        pattern = NeuralClassifierSklearn()
        pattern.fit(np.random.rand(10, input_dim), np.random.randint(0, 2, 10))
        anomaly = AnomalyDetectorSklearn()
        anomaly.fit(np.random.rand(20, input_dim))
        
        detector = HybridThreatDetector(rf, pattern, anomaly)
        
        # Initialize Malware Engine for File Scanning
        malware_engine = MalwareEngine(ensemble=detector)
        
        return {"message": "Phase IV & V Engines Initialized Successfully"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "network_engine": detector is not None,
        "malware_engine": malware_engine is not None
    }

# --- Phase IV Network Endpoints ---

@app.post("/predict", response_model=PredictionResponse)
async def predict(request: PredictionRequest):
    if detector is None:
        raise HTTPException(status_code=503, detail="Network engine not initialized")
    
    start_time = time.time()
    X = np.array(request.features).reshape(1, -1)
    result = detector.predict(X)
    latency = time.time() - start_time
    
    log_entry = logger.log_prediction(
        ip=request.source_ip,
        prediction=result['final_prediction'][0],
        score=result['final_score'][0],
        latency=latency
    )
    
    return PredictionResponse(
        prediction=log_entry["prediction"],
        threat_score=log_entry["threat_score"],
        severity=log_entry["severity"],
        confidence=result['confidence'][0],
        contributions={
            "rf": result['rf_contribution'][0],
            "pattern": result['cnn_contribution'][0],
            "anomaly": result['ae_contribution'][0]
        },
        latency_ms=log_entry["response_time_ms"]
    )

@app.get("/alerts/recent")
async def get_recent_alerts():
    return logger.get_recent_alerts()

# --- Phase V Malware Endpoints ---

@app.post("/malware/scan")
async def upload_and_scan(file: bytes = File(...), filename: str = Form(...)):
    if malware_engine is None:
        raise HTTPException(status_code=503, detail="Malware engine not initialized")
    
    result = malware_engine.scan_file(file, filename)
    scan_id = str(uuid.uuid4())[:8]
    result["id"] = scan_id
    result["timestamp"] = datetime.now().isoformat()
    result["is_malicious"] = result.get("detection") == "MALICIOUS"
    
    history.add_record(result)
    return result

@app.get("/malware/history")
async def get_malware_history(limit: int = 20):
    return history.get_history(limit)

@app.get("/malware/analytics")
async def get_malware_analytics():
    return history.get_analytics()
