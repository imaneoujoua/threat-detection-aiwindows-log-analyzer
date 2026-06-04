"""
Prediction script for real-time threat detection
"""

import sys
import os
import numpy as np
import json
import logging
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from src.threat_detector import ThreatDetector
from src.database import AlertDatabase
from src.utils import setup_logging, print_header, print_success, print_error, print_info

logger = setup_logging()

def predict_threat(features):
    """
    Predict threat for given features
    
    Args:
        features (dict or array): Network features
        
    Returns:
        dict: Prediction results
    """
    try:
        detector = ThreatDetector.load()
        
        # Convert to array if dict
        if isinstance(features, dict):
            feature_order = [
                'duration', 'protocol_type', 'bytes_sent', 'bytes_received',
                'nb_connections', 'error_rate', 'same_ip_count', 'port_number',
                'bytes_ratio', 'conn_per_second'
            ]
            features = np.array([
    features.get(f, 0)
    for f in feature_order
])
        
        # Make prediction
        result = detector.predict(np.array([features]))
        
        return result
    
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return {"error": str(e)}

def batch_predict(features_list):
    """
    Predict threats for multiple records
    
    Args:
        features_list (list): List of feature dicts or arrays
        
    Returns:
        list: Prediction results
    """
    try:
        detector = ThreatDetector.load()
        
        # Convert to array
        feature_arrays = []
        for features in features_list:
            if isinstance(features, dict):
                feature_order = [
                    'duration', 'protocol_type', 'bytes_sent', 'bytes_received',
                    'nb_connections', 'error_rate', 'same_ip_count', 'port_number',
                    'bytes_ratio', 'conn_per_second'
                ]
                feature_arrays.append(
    [
        features.get(f, 0)
        for f in feature_order
    ]
)
            else:
                feature_arrays.append(features)
        
        # Make predictions
        X = np.array(feature_arrays)
        results = detector.predict(X)
        
        return results if isinstance(results, list) else [results]
    
    except Exception as e:
        logger.error(f"Batch prediction error: {str(e)}")
        return []

def predict_and_log(features, ip_source="0.0.0.0"):
    """
    Predict threat and log to database
    
    Args:
        features (dict): Network features
        ip_source (str): Source IP address
    """
    result = predict_threat(features)
    
    if "error" not in result:
        db = AlertDatabase()
        
        # Log to database if threat detected
        if result['threat'] != 'Normal':
            db.insert_network_alert(
                ip_source=ip_source,
                attack_type=result['threat'],
                severity=result['severity'],
                confidence=result['confidence'],
                is_anomaly=result['is_anomaly'],
                details=json.dumps(result)
            )
            logger.info(f"Alert logged: {result['threat']} from {ip_source}")
    
    return result

def demo_predictions():
    """Run demo predictions with various attack scenarios"""
    print_header("CyberShield AI - Real-time Prediction Demo")
    
    # Load detector
    try:
        detector = ThreatDetector.load()
        print_success("Model loaded successfully")
    except Exception as e:
        print_error(f"Failed to load model: {str(e)}")
        print_info("Please run 'python train.py' first to train the model")
        return
    
    # Test cases
    test_cases = [
        {
            'name': 'Normal Web Browse',
            'ip': '192.168.1.100',
            'features': {
                'duration': 2.5, 'protocol_type': 0, 'bytes_sent': 480,
                'bytes_received': 1100, 'nb_connections': 4, 'error_rate': 0.02,
                'same_ip_count': 2, 'port_number': 443,
                'bytes_ratio': 0.44, 'conn_per_second': 1.6
            }
        },
        {
            'name': 'DoS/DDoS Attack',
            'ip': '10.0.1.50',
            'features': {
                'duration': 0.03, 'protocol_type': 0, 'bytes_sent': 42,
                'bytes_received': 85, 'nb_connections': 950, 'error_rate': 0.78,
                'same_ip_count': 600, 'port_number': 80,
                'bytes_ratio': 0.49, 'conn_per_second': 31667
            }
        },
        {
            'name': 'SSH Intrusion Attempt',
            'ip': '203.0.113.45',
            'features': {
                'duration': 22.0, 'protocol_type': 0, 'bytes_sent': 300,
                'bytes_received': 750, 'nb_connections': 2, 'error_rate': 0.35,
                'same_ip_count': 1, 'port_number': 22,
                'bytes_ratio': 0.40, 'conn_per_second': 0.09
            }
        },
        {
            'name': 'Malware C&C Communication',
            'ip': '198.51.100.15',
            'features': {
                'duration': 31.5, 'protocol_type': 1, 'bytes_sent': 195,
                'bytes_received': 200, 'nb_connections': 12, 'error_rate': 0.15,
                'same_ip_count': 9, 'port_number': 4444,
                'bytes_ratio': 0.97, 'conn_per_second': 0.38
            }
        },
        {
            'name': 'Phishing Attack',
            'ip': '192.0.2.75',
            'features': {
                'duration': 4.8, 'protocol_type': 0, 'bytes_sent': 1950,
                'bytes_received': 4900, 'nb_connections': 18, 'error_rate': 0.08,
                'same_ip_count': 6, 'port_number': 80,
                'bytes_ratio': 0.39, 'conn_per_second': 3.75
            }
        },
        {
            'name': 'Brute Force RDP',
            'ip': '198.0.100.88',
            'features': {
                'duration': 0.15, 'protocol_type': 0, 'bytes_sent': 145,
                'bytes_received': 95, 'nb_connections': 95, 'error_rate': 0.88,
                'same_ip_count': 75, 'port_number': 3389,
                'bytes_ratio': 1.53, 'conn_per_second': 633.3
            }
        }
    ]
    
    print_info("\nRunning predictions...\n")
    
    for test in test_cases:
        result = predict_and_log(test['features'], test['ip'])
        
        severity_emoji = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'none': '🟢'
        }
        
        emoji = severity_emoji.get(result.get('severity', 'none'), '⚪')
        
        print(f"{emoji} {test['name']}")
        print(f"   IP: {test['ip']}")
        print(f"   Threat: {result.get('threat', 'Unknown')}")
        print(f"   Confidence: {result.get('confidence', 0)*100:.1f}%")
        print(f"   Severity: {result.get('severity', 'unknown')}")
        print(f"   Anomaly: {'⚠️ Yes' if result.get('is_anomaly') else '✓ No'}\n")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="CyberShield AI - Threat Prediction")
    parser.add_argument('--demo', action='store_true', help='Run demo predictions')
    parser.add_argument('--features', type=str, help='JSON features for single prediction')
    parser.add_argument('--ip', type=str, default='0.0.0.0', help='Source IP address')
    
    args = parser.parse_args()
    
    if args.demo:
        demo_predictions()
    elif args.features:
        features = json.loads(args.features)
        result = predict_and_log(features, args.ip)
        print(json.dumps(result, indent=2))
    else:
        demo_predictions()
