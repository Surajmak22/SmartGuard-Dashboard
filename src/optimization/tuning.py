import optuna
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
import tensorflow as tf
from ..models.cnn_model import CNNClassifier
from ..models.autoencoder import AutoencoderAnomalyDetector

def optimize_rf(X, y):
    def objective(trial):
        n_estimators = trial.suggest_int('n_estimators', 50, 300)
        max_depth = trial.suggest_int('max_depth', 5, 30)
        
        clf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=42,
            class_weight='balanced'
        )
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)
        return f1_score(y_test, preds)

    study = optuna.create_study(direction='maximize')
    study.optimize(objective, n_trials=20)
    return study.best_params

def optimize_cnn(X, y):
    def objective(trial):
        lr = trial.suggest_float('lr', 1e-4, 1e-2, log=True)
        filters = trial.suggest_categorical('filters', [16, 32, 64])
        
        model = CNNClassifier(input_shape=(X.shape[1], 1))
        optimizer = tf.keras.optimizers.Adam(learning_rate=lr)
        model.compile(optimizer=optimizer, loss='binary_crossentropy', metrics=['accuracy'])
        
        # Simple training loop for tuning
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        model.fit(X_train, y_train, epochs=5, batch_size=32, verbose=0)
        
        preds = (model.predict(X_test) > 0.5).astype(int).flatten()
        return f1_score(y_test, preds)

    study = optuna.create_study(direction='maximize')
    study.optimize(objective, n_trials=10)
    return study.best_params

def optimize_autoencoder(X):
    def objective(trial):
        bottleneck = trial.suggest_int('bottleneck', 4, 16)
        
        model = AutoencoderAnomalyDetector(input_dim=X.shape[1], bottleneck_dim=bottleneck)
        model.compile(optimizer='adam', loss='mae')
        
        X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)
        model.fit(X_train, X_train, epochs=10, batch_size=32, verbose=0)
        
        reconstructions = model.predict(X_test)
        loss = tf.keras.losses.mae(reconstructions, X_test)
        # We want to minimize reconstruction error on normal data
        return np.mean(loss)

    study = optuna.create_study(direction='minimize')
    study.optimize(objective, n_trials=10)
    return study.best_params
