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
    """
    Generate synthetic network traffic data
    """

    np.random.seed(42)

    records = []

    for _ in range(n_samples):

        label = np.random.choice(
            [0, 1, 2, 3, 4, 5],
            p=[0.50, 0.15, 0.10, 0.10, 0.10, 0.05]
        )

        if label == 0:
            duration = np.random.exponential(2)
            nb_connections = np.random.poisson(5)
            error_rate = np.random.beta(1, 20)

        elif label == 1:
            duration = np.random.exponential(0.05)
            nb_connections = np.random.poisson(700) + 300
            error_rate = np.random.beta(6, 2)

        elif label == 2:
            duration = np.random.exponential(18)
            nb_connections = np.random.poisson(3)
            error_rate = np.random.beta(3, 5)

        elif label == 3:
            duration = np.random.normal(30, 5)
            nb_connections = np.random.poisson(10)
            error_rate = np.random.beta(2, 8)

        elif label == 4:
            duration = np.random.exponential(5)
            nb_connections = np.random.poisson(15)
            error_rate = np.random.beta(1, 10)

        else:
            duration = np.random.exponential(0.2)
            nb_connections = np.random.poisson(80) + 20
            error_rate = np.random.beta(7, 1)

        records.append({
            "duration": abs(duration),
            "protocol_type": np.random.randint(0, 3),
            "bytes_sent": abs(np.random.normal(500, 200)),
            "bytes_received": abs(np.random.normal(1200, 400)),
            "nb_connections": nb_connections,
            "error_rate": error_rate,
            "same_ip_count": np.random.poisson(5),
            "port_number": np.random.choice(
                [21, 22, 23, 53, 80, 443, 3389]
            ),
            "label": label
        })

    df = pd.DataFrame(records)

    return df


def train_threat_detector():

    print_header(
        "CyberShield AI - Training Pipeline"
    )

    print_info("Generating dataset...")

    df = generate_synthetic_data(5000)

    print_success(
        f"{len(df)} samples generated"
    )

    print_info("Preprocessing data...")

    preprocessor = DataPreprocessor()

    df = preprocessor.handle_missing_values(
        df,
        strategy="mean"
    )

    df = preprocessor.remove_duplicates(df)

    print_success("Preprocessing completed")

    print_info("Feature engineering...")

    engineer = FeatureEngineer()

    df = engineer.create_behavioral_features(df)

    features = [
        "duration",
        "protocol_type",
        "bytes_sent",
        "bytes_received",
        "nb_connections",
        "error_rate",
        "same_ip_count",
        "port_number",
        "bytes_ratio",
        "conn_per_second"
    ]

    X = df[features].values

    y = df["label"].values

    from sklearn.model_selection import (
        train_test_split
    )

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y
        )
    )

    print_success(
        f"Train: {len(X_train)} | Test: {len(X_test)}"
    )

    detector = ThreatDetector()

    detector.train(
        X_train,
        y_train,
        X_normal=X_train[y_train == 0]
    )

    print_success("Training completed")

    metrics = detector.evaluate(
        X_test,
        y_test
    )

    print_success(
        f"Accuracy = {metrics['accuracy']:.4f}"
    )

    print_success(
        f"Precision = {metrics['precision']:.4f}"
    )

    print_success(
        f"Recall = {metrics['recall']:.4f}"
    )

    print_success(
        f"F1 Score = {metrics['f1_score']:.4f}"
    )

    os.makedirs(
        "data/models",
        exist_ok=True
    )

    detector.save()

    print_success("Models saved")

    os.makedirs(
        "reports",
        exist_ok=True
    )

    report = {
        "timestamp":
        datetime.now().isoformat(),

        "metrics":
        metrics
    }

    save_json(
        report,
        "reports/model_metrics.json"
    )

    db = AlertDatabase()

    db.insert_model_metrics(
        accuracy=metrics["accuracy"],
        precision=metrics["precision"],
        recall=metrics["recall"],
        f1_score=metrics["f1_score"],
        roc_auc=0,
        notes="Training completed"
    )

    print_success(
        "Metrics stored in database"
    )

    print_header(
        "Training Finished Successfully"
    )

    return detector


if __name__ == "__main__":
    train_threat_detector()
```
