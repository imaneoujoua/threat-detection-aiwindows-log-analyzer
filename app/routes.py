"""
Flask REST API for CyberShield AI
"""

import sys
import os
import json
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.threat_detector import ThreatDetector
from src.windows_log_analyzer import WindowsLogAnalyzer
from src.database import AlertDatabase
from src.utils import setup_logging

app = Flask(__name__)
CORS(app)

logger = setup_logging()

# Global detector instance
detector = None

def load_detector():
    """Load threat detector model"""
    global detector
    try:
        detector = ThreatDetector.load()
        logger.info("Threat detector loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load detector: {str(e)}")
        detector = None

@app.before_request
def before_request():
    """Initialize detector if needed"""
    global detector
    if detector is None:
        load_detector()

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "version": "2.0.0",
        "model_loaded": detector is not None
    })

@app.route('/api/predict', methods=['POST'])
def predict():
    """
    Predict threat for single record
    
    POST /api/predict
    Content-Type: application/json
    
    {
      "duration": 2.5,
      "protocol_type": 0,
      "bytes_sent": 480,
      "bytes_received": 1100,
      "nb_connections": 4,
      "error_rate": 0.02,
      "same_ip_count": 2,
      "port_number": 443,
      "bytes_ratio": 0.44,
      "conn_per_second": 1.6,
      "ip_source": "192.168.1.100"
    }
    """
    try:
        if detector is None:
            return jsonify({"error": "Model not loaded"}), 503
        
        data = request.get_json()
        
        # Extract features
        feature_order = [
            'duration', 'protocol_type', 'bytes_sent', 'bytes_received',
            'nb_connections', 'error_rate', 'same_ip_count', 'port_number',
            'bytes_ratio', 'conn_per_second'
        ]
        
        features = np.array([data[f] for f in feature_order])
        
        # Make prediction
        result = detector.predict(features)
        
        # Log to database if not normal
        ip_source = data.get('ip_source', '0.0.0.0')
        if result['threat'] != 'Normal':
            db = AlertDatabase()
            db.insert_network_alert(
                ip_source=ip_source,
                attack_type=result['threat'],
                severity=result['severity'],
                confidence=result['confidence'],
                bytes_sent=data.get('bytes_sent'),
                nb_connections=data.get('nb_connections'),
                is_anomaly=result['is_anomaly'],
                details=json.dumps(result)
            )
        
        return jsonify(result), 200
    
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.route('/api/predict-batch', methods=['POST'])
def predict_batch():
    """
    Predict threats for multiple records
    
    POST /api/predict-batch
    Content-Type: application/json
    
    {
      "events": [
        {"duration": 2.5, "protocol_type": 0, ...},
        {"duration": 0.03, "protocol_type": 0, ...}
      ]
    }
    """
    try:
        if detector is None:
            return jsonify({"error": "Model not loaded"}), 503
        
        data = request.get_json()
        events = data.get('events', [])
        
        feature_order = [
            'duration', 'protocol_type', 'bytes_sent', 'bytes_received',
            'nb_connections', 'error_rate', 'same_ip_count', 'port_number',
            'bytes_ratio', 'conn_per_second'
        ]
        
        # Convert to array
        features_array = []
        for event in events:
            features_array.append([event[f] for f in feature_order])
        
        X = np.array(features_array)
        
        # Make predictions
        results = detector.predict(X)
        if not isinstance(results, list):
            results = [results]
        
        return jsonify({
            "total": len(results),
            "predictions": results
        }), 200
    
    except Exception as e:
        logger.error(f"Batch prediction error: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.route('/api/analyze-logs', methods=['POST'])
def analyze_logs():
    """
    Analyze Windows Event Log CSV
    
    POST /api/analyze-logs
    Content-Type: application/json
    
    {
      "csv_path": "data/raw/logs.csv"
    }
    """
    try:
        data = request.get_json()
        csv_path = data.get('csv_path')
        
        if not csv_path or not os.path.exists(csv_path):
            return jsonify({"error": "Invalid or missing csv_path"}), 400
        
        analyzer = WindowsLogAnalyzer()
        results = analyzer.load_and_analyze(csv_path)
        
        return jsonify(results), 200
    
    except Exception as e:
        logger.error(f"Log analysis error: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.route('/api/stats', methods=['GET'])
def stats():
    """Get database statistics"""
    try:
        db = AlertDatabase()
        stats_data = db.get_statistics()
        return jsonify(stats_data), 200
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get recent network alerts"""
    try:
        limit = request.args.get('limit', 100, type=int)
        attack_type = request.args.get('type', None)
        
        db = AlertDatabase()
        alerts = db.get_network_alerts(limit=limit, attack_type=attack_type)
        
        return jsonify({
            "total": len(alerts),
            "alerts": [
                {
                    "id": a[0],
                    "timestamp": a[1],
                    "ip_source": a[2],
                    "attack_type": a[3],
                    "severity": a[4],
                    "confidence": a[5]
                }
                for a in alerts
            ]
        }), 200
    except Exception as e:
        logger.error(f"Alerts error: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.route('/api/windows-threats', methods=['GET'])
def get_windows_threats():
    """Get Windows security threats"""
    try:
        limit = request.args.get('limit', 100, type=int)
        threat_type = request.args.get('type', None)
        
        db = AlertDatabase()
        threats = db.get_windows_threats(limit=limit, threat_type=threat_type)
        
        return jsonify({
            "total": len(threats),
            "threats": [
                {
                    "id": t[0],
                    "timestamp": t[1],
                    "threat_type": t[2],
                    "user_target": t[3],
                    "severity": t[4],
                    "severity_score": t[5]
                }
                for t in threats
            ]
        }), 200
    except Exception as e:
        logger.error(f"Threats error: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    load_detector()
    app.run(host='0.0.0.0', port=5000, debug=False)
