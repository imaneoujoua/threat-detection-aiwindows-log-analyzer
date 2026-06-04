"""
Training script for CyberShield AI models
"""

import sys
import os
import numpy as np
import pandas as pd
import logging
import json
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from src.data_loader import NetworkLogLoader
from src.data_preprocessor import DataPreprocessor
from src.feature_engineering import FeatureEngineer
from src.threat_detector import ThreatDetector
from src.database import AlertDatabase
from src.utils import setup_logging, print_header, print_success, print_error, print_info, save_json

logger = setup_logging()

def generate_synthetic_data(n_samples=5000):
    """Generate synthetic network traffic data"""
    print_info(f"Generating {n_samples} synthetic network samples...")
    
    np.random.seed(42)
    
    records = []
    n_each = n_samples // 6
    
    # Normal traffic
    for _ in range(n_each * 3):
        records.append({
            'duration': np.random.exponential(2),
            'protocol_type': np.random.choice([0, 1, 2], p=[0.6, 0.3, 0.1]),
            'bytes_sent': np.random.normal(500, 200),
            'bytes_received': np.random.normal(1200, 400),
            'nb_connections': np.random.poisson(5),
            'error_rate': np.random.beta(1, 20),
            'same_ip_count': np.random.poisson(2),
            'port_number': np.random.choice([80, 443, 22, 8080], p=[0.4, 0.4, 0.1, 0.1]),
            'label': 0  # Normal
        })
    
    # DoS/DDoS
    for _ in range(n_each):
        records.append({
            'duration': np.random.exponential(0.05),
            'protocol_type': np.random.choice([0, 2], p=[0.7, 0.3]),
            'bytes_sent': np.random.normal(45, 8),
            'bytes_received': np.random.normal(90, 15),
            'nb_connections': np.random.poisson(700) + 300,
            'error_rate': np.random.beta(6, 2),
            'same_ip_count': np.random.poisson(300) + 150,
            'port_number': np.random.choice([80, 443, 53]),
            'label': 1  # DoS
        })
    
    # Intrusion
    for _ in range(n_each):
        records.append({
            'duration': np.random.exponential(18),
            'protocol_type': np.random.choice([0, 1], p=[0.8, 0.2]),
            'bytes_sent': np.random.normal(300, 100),
            'bytes_received': np.random.normal(800, 300),
            'nb_connections': np.random.poisson(3),
            'error_rate': np.random.beta(3, 5),
            'same_ip_count': np.random.poisson(1),
            'port_number': np.random.choice([22, 23, 3389, 1433]),
            'label': 2  # Intrusion
        })
    
    # Malware
    for _ in range(n_each):
        records.append({
            'duration': np.random.normal(30, 5),
            'protocol_type': np.random.choice([0, 1], p=[0.5, 0.5]),
            'bytes_sent': np.random.normal(200, 50),
            'bytes_received': np.random.normal(200, 50),
            'nb_connections': np.random.poisson(10),
            'error_rate': np.random.beta(2, 8),
            'same_ip_count': np.random.poisson(8),
            'port_number': np.random.choice([6667, 4444, 1337, 8888]),
            'label': 3  # Malware
        })
    
    # Phishing
    for _ in range(n_each):
        records.append({
            'duration': np.random.exponential(5),
            'protocol_type': 0,
            'bytes_sent': np.random.normal(2000, 500),
            'bytes_received': np.random.normal(5000, 1000),
            'nb_connections': np.random.poisson(15),
            'error_rate': np.random.beta(1, 10),
            'same_ip_count': np.random.poisson(5),
            'port_number': np.random.choice([80, 443], p=[0.7, 0.3]),
            'label': 4  # Phishing
        })
    
    # Brute Force
    for _ in range(n_each):
        records.append({
            'duration': np.random.exponential(0.2),
            'protocol_type': 0,
            'bytes_sent': np.random.normal(150, 30),
            'bytes_received': np.random.normal(100, 20),
            'nb_connections': np.random.poisson(80) + 20,
            'error_rate': np.random.beta(7, 1),
            'same_ip_count': np.random.poisson(60) + 20,
            'port_number': np.random.choice([22, 3389, 21, 23]),
            'label': 5  # BruteForce
        })
    
    df = pd.DataFrame(records)
    
    # Create derived features
    df['bytes_ratio'] = df['bytes_sent'] / (df['bytes_received'] + 1)
    df['conn_per_second'] = df['nb_connections'] / (df['duration'] + 0.01)
    
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return df

def train_threat_detector():
    """Main training pipeline"""
    print_header("CyberShield AI - Model Training Pipeline")
    
    # Generate data
    print_info("Step 1: Data Generation")
    df = generate_synthetic_data(n_samples=5000)
    print_success(f"Generated {len(df)} samples")
    
    # Preprocessing
    print_info("\nStep 2: Data Preprocessing")
    preprocessor = DataPreprocessor()
    df = preprocessor.handle_missing_values(df, strategy="mean")
    df = preprocessor.remove_duplicates(df)
    print_success("Data preprocessing completed")
    
    # Feature Engineering
    print_info("\nStep 3: Feature Engineering")
    engineer = FeatureEngineer()
    df = engineer.create_behavioral_features(df)
    df = engineer.create_statistical_features(df)
    print_success("Features engineered")
    
    # Prepare data
    features = [
        'duration', 'protocol_type', 'bytes_sent', 'bytes_received',
        'nb_connections', 'error_rate', 'same_ip_count', 'port_number',
        'bytes_ratio', 'conn_per_second'
    ]
    
    X = df[features].values
    y = df['label'].values
    
    # Split data
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)
    print_info(f"\nStep 4: Train/Test Split")
    print_success(f"Training samples: {len(X_train)}, Test samples: {len(X_test)}")
    
    # Train detector
    print_info("\nStep 5: Model Training")
    config = {
        'n_estimators': 200,
        'max_depth': 15,
        'min_samples_split': 4,
        'random_state': 42
    }
    
    detector = ThreatDetector(config)
    detector.train(X_train, y_train, X_normal=X_train[y_train == 0])
    print_success("Model training completed")
    
    # Evaluate
    print_info("\nStep 6: Model Evaluation")
    metrics = detector.evaluate(X_test, y_test)
    print_success(f"Accuracy: {metrics['accuracy']:.4f}")
    print_success(f"Precision: {metrics['precision']:.4f}")
    print_success(f"Recall: {metrics['recall']:.4f}")
    print_success(f"F1-Score: {metrics['f1_score']:.4f}")
    
    # Save models
    print_info("\nStep 7: Model Persistence")
    os.makedirs("data/models", exist_ok=True)
    detector.save()
    print_success("Models saved successfully")
    
    # Save metrics
    os.makedirs("reports", exist_ok=True)
    metrics_report = {
        "timestamp": datetime.now().isoformat(),
        "metrics": metrics,
        "config": config
    }
    save_json(metrics_report, "reports/model_metrics.json")
    
    # Store in database
    print_info("\nStep 8: Database Storage")
    db = AlertDatabase()
    db.insert_model_metrics(
        accuracy=metrics['accuracy'],
        precision=metrics['precision'],
        recall=metrics['recall'],
        f1_score=metrics['f1_score'],
        roc_auc=metrics.get('roc_auc', 0),
        notes="Model training completed successfully"
    )
    print_success("Metrics stored in database")
    
    print_header("Training Pipeline Completed Successfully!")
    return detector

if __name__ == "__main__":
    train_threat_detector()
