"""
Threat Detection module - Main AI detector
Uses Random Forest and Isolation Forest for threat detection
"""

import numpy as np
import pickle
import logging
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)

logger = logging.getLogger(__name__)

THREAT_LABELS = {
    0: "Normal",
    1: "DoS/DDoS",
    2: "Intrusion",
    3: "Malware",
    4: "Phishing",
    5: "BruteForce"
}

SEVERITY_LEVELS = {
    "Normal": "none",
    "DoS/DDoS": "critical",
    "Intrusion": "high",
    "Malware": "high",
    "Phishing": "medium",
    "BruteForce": "critical"
}

class ThreatDetector:
    """
    Hybrid threat detection system
    - Random Forest for known threats
    - Isolation Forest for anomaly detection (zero-day)
    """
    
    def __init__(self, config=None):
        """
        Initialize ThreatDetector
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config or {}
        self.rf_model = None
        self.iso_model = None
        self.scaler = StandardScaler()
        self.trained = False
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def train(self, X_train, y_train, X_normal=None, cross_validate=False):
        """
        Train both Random Forest and Isolation Forest models
        
        Args:
            X_train (array): Training features
            y_train (array): Training labels
            X_normal (array): Normal data for Isolation Forest training
            cross_validate (bool): Whether to perform cross-validation
            
        Returns:
            dict: Training metrics
        """
        self.logger.info("Training threat detection models...")
        
        # Scale training data
        X_scaled = self.scaler.fit_transform(X_train)
        
        # Train Random Forest
        self.logger.info("Training Random Forest classifier...")
        self.rf_model = RandomForestClassifier(
            n_estimators=self.config.get('n_estimators', 200),
            max_depth=self.config.get('max_depth', 15),
            min_samples_split=self.config.get('min_samples_split', 4),
            class_weight="balanced",
            random_state=self.config.get('random_state', 42),
            n_jobs=-1
        )
        self.rf_model.fit(X_scaled, y_train)
        self.logger.info("Random Forest training completed")
        
        # Train Isolation Forest on normal data
        self.logger.info("Training Isolation Forest for anomaly detection...")
        if X_normal is None:
            X_normal = X_scaled[y_train == 0]
        
        self.iso_model = IsolationForest(
            n_estimators=120,
            contamination=0.08,
            random_state=42
        )
        self.iso_model.fit(X_normal)
        self.logger.info("Isolation Forest training completed")
        
        self.trained = True
        return {"status": "Models trained successfully"}
    
    def predict(self, X, return_proba=True):
        """
        Predict threat classification for input data
        
        Args:
            X (array): Input features (single or multiple)
            return_proba (bool): Whether to return probabilities
            
        Returns:
            dict or list: Prediction results
        """
        if not self.trained:
            raise RuntimeError("Model not trained. Call train() first.")
        
        # Ensure 2D array
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        
        X_scaled = self.scaler.transform(X)
        
        # Random Forest predictions
        predictions = self.rf_model.predict(X_scaled)
        if return_proba:
            probabilities = self.rf_model.predict_proba(X_scaled)
        
        # Isolation Forest anomaly scores
        iso_predictions = self.iso_model.predict(X_scaled)
        iso_scores = self.iso_model.score_samples(X_scaled)
        
        # Format results
        results = []
        for i in range(len(X)):
            pred_label = int(predictions[i])
            threat_name = THREAT_LABELS.get(pred_label, "Unknown")
            
            result = {
                "threat": threat_name,
                "threat_id": pred_label,
                "severity": SEVERITY_LEVELS.get(threat_name, "unknown"),
                "confidence": float(probabilities[i][pred_label]) if return_proba else None,
                "is_anomaly": iso_predictions[i] == -1,
                "anomaly_score": float(iso_scores[i])
            }
            
            if return_proba:
                result["probabilities"] = {
                    THREAT_LABELS.get(j, "Unknown"): float(probabilities[i][j])
                    for j in range(len(probabilities[i]))
                }
            
            results.append(result)
        
        # Return single dict if single input
        return results[0] if len(results) == 1 else results
    
    def evaluate(self, X_test, y_test):
        """
        Evaluate model performance
        
        Args:
            X_test (array): Test features
            y_test (array): Test labels
            
        Returns:
            dict: Performance metrics
        """
        if not self.trained:
            raise RuntimeError("Model not trained. Call train() first.")
        
        X_scaled = self.scaler.transform(X_test)
        y_pred = self.rf_model.predict(X_scaled)
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
        recall = recall_score(y_test, y_pred, average="weighted", zero_division=0)
        f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
        
        metrics = {
            "accuracy": round(float(accuracy), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "classification_report": classification_report(
                y_test, y_pred,
                target_names=[THREAT_LABELS[i] for i in range(len(THREAT_LABELS))]
            )
        }
        
        self.logger.info(f"Model Evaluation - Accuracy: {accuracy:.4f}, F1: {f1:.4f}")
        return metrics
    
    def feature_importance(self):
        """
        Get feature importance from Random Forest
        
        Returns:
            dict: Feature importance scores
        """
        if not self.trained or self.rf_model is None:
            return {}
        
        return dict(enumerate(self.rf_model.feature_importances_))
    
    def save(self, model_path="data/models/random_forest_model.pkl",
             iso_path="data/models/isolation_forest_model.pkl",
             scaler_path="data/models/scaler.pkl"):
        """
        Save trained models to disk
        
        Args:
            model_path (str): Path to save Random Forest model
            iso_path (str): Path to save Isolation Forest model
            scaler_path (str): Path to save scaler
        """
        import os
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        with open(model_path, "wb") as f:
    pickle.dump(self.rf_model, f)

with open(iso_path, "wb") as f:
    pickle.dump(self.iso_model, f)

with open(scaler_path, "wb") as f:
    pickle.dump(self.scaler, f)
        
        self.logger.info(f"Models saved to {model_path}, {iso_path}, {scaler_path}")
    
    @classmethod
    def load(cls, model_path="data/models/random_forest_model.pkl",
             iso_path="data/models/isolation_forest_model.pkl",
             scaler_path="data/models/scaler.pkl"):
        """
        Load trained models from disk
        
        Args:
            model_path (str): Path to Random Forest model
            iso_path (str): Path to Isolation Forest model
            scaler_path (str): Path to scaler
            
        Returns:
            ThreatDetector: Loaded detector instance
        """
        detector = cls()
        with open(model_path, "rb") as f:
    detector.rf_model = pickle.load(f)

with open(iso_path, "rb") as f:
    detector.iso_model = pickle.load(f)

with open(scaler_path, "rb") as f:
    detector.scaler = pickle.load(f)
        detector.trained = True
        
        detector.logger.info(
    f"Models loaded from {model_path}, {iso_path}, {scaler_path}"
)
        return detector


if __name__ == "__main__":
    print("ThreatDetector module loaded successfully")
