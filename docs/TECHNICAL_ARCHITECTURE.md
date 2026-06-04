# Architecture Technique - CyberShield AI

## 🏗️ Vue d'Ensemble Architecturale

```
┌─────────────────────────────────────────────────────────┐
│                    USER INTERFACE LAYER                 │
├─────────────────────────────────────────────────────────┤
│  Dashboard (Dash)  │  REST API (Flask)  │  CLI Scripts  │
├─────────────────────────────────────────────────────────┤
│                    APPLICATION LAYER                    │
├─────────────────────────────────────────────────────────┤
│  Threat Detector  │  Anomaly Detector  │  Log Analyzer  │
├─────────────────────────────────────────────────────────┤
│                   MACHINE LEARNING LAYER                │
├─────────────────────────────────────────────────────────┤
│ Random Forest (200) │ Isolation Forest │ Feature Engineer│
├─────────────────────────────────────────────────────────┤
│                     DATA LAYER                          │
├─────────────────────────────────────────────────────────┤
│  Data Loader  │  Preprocessor  │  Feature Engineering  │
├─────────────────────────────────────────────────────────┤
│                   PERSISTENCE LAYER                     │
├─────────────────────────────────────────────────────────┤
│     SQLite Database    │    Pickle Models    │  CSV     │
└─────────────────────────────────────────────────────────┘
```

## 📦 Composants Principaux

### 1. **Data Pipeline**
```
Raw Data (CSV) → DataLoader → DataPreprocessor → FeatureEngineer → ThreatDetector → AlertDB
```

### 2. **Threat Detection Models**

**Random Forest (Modèle Principal)**
- 200 arbres de décision
- Max depth: 15
- Classe balancée: Oui
- Validation croisée: 5-folds stratifiée
- Accuracy cible: 99%

**Isolation Forest (Anomalies)**
- 120 arbres
- Contamination: 8%
- Détecte les attaques zero-day
- Score: -1 (anomalie) ou 1 (normal)

## 🔄 Flux de Données

### Entraînement
```
1. DataGenerator → 5000 samples
2. DataPreprocessor → Nettoyage
3. FeatureEngineer → 10 features
4. Train-Test Split → 80/20
5. ThreatDetector.train → RF + IF
6. Model Evaluation → Métriques
7. Model Persistence → Pickle
```

### Prédiction
```
1. Raw Input (10 features)
2. Scaling (StandardScaler)
3. RF Prediction (classe 0-5)
4. IF Anomaly Score
5. Probabilités par classe
6. Format JSON
7. Database Logging
```

## 🗄️ Schéma Base de Données

**network_alerts**: Alertes réseau détectées
**windows_threats**: Menaces Windows analysées
**model_metrics**: Métriques de performance du modèle

## 📊 Performance

- Prédiction simple: < 100ms
- Batch (1000): < 1s
- Analyse logs: < 5s
- Global: < 3s max

## 🔐 Sécurité

- HTTPS en production
- API Key authentication
- DB encryptée (SQLCipher)
- Container isolation
