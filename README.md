# 🛡️ CyberShield AI - Threat Detection System

> **Système de détection d'intrusion par Intelligence Artificielle** pour analyser les **journaux Windows** et **logs réseau** en temps réel.

## 🎯 Objectifs du Projet

- ✅ **Détecter 6 types de menaces** : Normal, DoS/DDoS, Intrusion, Malware, Phishing, Brute-Force
- ✅ **Analyser 10 354 événements Windows** réels pour identifier les attaques actives
- ✅ **Atteindre 99% de précision** avec validation croisée stratifiée (5 folds)
- ✅ **Détection d'anomalies** pour les attaques zero-day (inconnues)
- ✅ **Dashboard interactif** en temps réel
- ✅ **Temps de réponse < 3 secondes** par prédiction

---

## 📊 Dataset Analysé

### Événements Windows Détectés (10 354 événements)

| Event ID | Événement | Nombre | Risque | Catégorie |
|----------|-----------|--------|--------|-----------|
| **4625** | Échec de connexion | 732 | 🔴 CRITIQUE | Brute-Force |
| **4672** | Privilège élevé | 4 071 | 🟡 MOYEN | Intrusion |
| **4624** | Connexion réussie | 3 752 | 🟢 NORMAL | Normal |
| **5379/5382** | Credential Manager | 170 | 🔴 CRITIQUE | Malware |
| **4798/4799** | Énumération | 796 | 🟠 ÉLEVÉ | Intrusion |
| **4616** | Heure modifiée | 77 | 🟠 ÉLEVÉ | Malware |
| **4720/4722** | Compte créé | 50 | 🟠 ÉLEVÉ | Intrusion |

---

## 🏗️ Architecture du Projet

```
threat-detection-aiwindows-log-analyzer/
│
├── 📁 data/
│   ├── raw/
│   │   └── logs_simulation_bruts.csv          # Données brutes (733 KB)
│   ├── processed/
│   │   ├── cleaned_data.csv
│   │   ├── features_engineered.csv
│   │   └── train_test_split.pkl
│   └── models/
│       ├── random_forest_model.pkl
│       ├── isolation_forest_model.pkl
│       ├── scaler.pkl
│       └── model_metadata.json
│
├── 📁 src/
│   ├── __init__.py
│   ├── data_loader.py                        # Chargement des données
│   ├── data_preprocessor.py                  # Nettoyage et préparation
│   ├── feature_engineering.py                # Création des features
│   ├── windows_log_analyzer.py               # Analyse logs Windows
│   ├── threat_detector.py                    # Détecteur IA principal
│   ├── anomaly_detector.py                   # Détection d'anomalies
│   ├── database.py                           # Gestion SQLite
│   └── utils.py                              # Utilitaires
│
├── 📁 notebooks/
│   ├── 01_exploratory_data_analysis.ipynb    # EDA
│   ├── 02_data_preparation.ipynb             # Préparation
│   ├── 03_model_training.ipynb               # Entraînement
│   └── 04_model_evaluation.ipynb             # Évaluation
│
├── 📁 app/
│   ├── __init__.py
│   ├── dashboard.py                          # Dashboard Dash
│   ├── routes.py                             # Routes API
│   ├── callbacks.py                          # Callbacks Dash
│   └── utils_app.py                          # Utilitaires app
│
├── 📁 tests/
│   ├── __init__.py
│   ├── test_data_loader.py
│   ├── test_threat_detector.py
│   └── test_feature_engineering.py
│
├── 📁 reports/
│   ├── results.json                          # Résultats exportés
│   └── model_metrics.json                    # Métriques du modèle
│
├── 📁 docs/
│   └── (documentation)
│
├── 📄 config.yaml                            # Configuration
├── 📄 requirements.txt                       # Dépendances
├── 📄 .gitignore                             # Git ignore
├── 📄 main.py                                # Point d'entrée principal
└── 📄 README.md                              # Documentation
```

---

## 🚀 Installation Rapide

### Prérequis
- Python 3.8+
- pip ou conda

### Étapes d'installation

```bash
# 1. Cloner le repository
git clone https://github.com/imaneoujoua/threat-detection-aiwindows-log-analyzer.git
cd threat-detection-aiwindows-log-analyzer

# 2. Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Lancer le pipeline complet
python main.py --logs data/raw/logs_simulation_bruts.csv

# 5. Lancer le dashboard
python -m app.dashboard
```

Dashboard disponible à : `http://localhost:8050`

---

## 💻 Utilisation

### 1. Analyse Complète

```python
from src.threat_detector import ThreatDetector
from src.windows_log_analyzer import WindowsLogAnalyzer

# Analyser les logs Windows
analyzer = WindowsLogAnalyzer()
results = analyzer.load_and_analyze("data/raw/logs_simulation_bruts.csv")

# Charger le modèle et faire une prédiction
detector = ThreatDetector.load("data/models/random_forest_model.pkl")
prediction = detector.predict({
    'duration': 2.5,
    'protocol_type': 0,
    'bytes_sent': 480,
    'bytes_received': 1100,
    'nb_connections': 4,
    'error_rate': 0.02,
    'same_ip_count': 2,
    'port_number': 443,
    'bytes_ratio': 0.44,
    'conn_per_second': 1.6
})

print(prediction)
# Output: 
# {
#     'label': 'Normal',
#     'confidence': 0.9876,
#     'severity': 'none',
#     'is_anomaly': False,
#     'anomaly_score': -0.1234
# }
```

### 2. Notebooks Jupyter

```bash
# EDA - Analyse Exploratoire
jupyter notebook notebooks/01_exploratory_data_analysis.ipynb

# Préparation des Données
jupyter notebook notebooks/02_data_preparation.ipynb

# Entraînement des Modèles
jupyter notebook notebooks/03_model_training.ipynb

# Évaluation
jupyter notebook notebooks/04_model_evaluation.ipynb
```

### 3. API REST

```bash
# Démarrer le serveur API
python app/routes.py
```

**Endpoints disponibles :**

- `POST /api/predict` - Prédiction simple
- `POST /api/predict-batch` - Prédictions en batch
- `GET /api/model/metrics` - Métriques du modèle
- `POST /api/analyze-logs` - Analyser les logs Windows

---

## 🤖 Modèles Utilisés

### Modèle Principal : Random Forest
```
- n_estimators: 200
- max_depth: 15
- min_samples_split: 4
- class_weight: balanced
- cv_folds: 5 (validation croisée stratifiée)
```

### Détection d'Anomalies : Isolation Forest
```
- n_estimators: 120
- contamination: 0.08
- Entraîné sur les connexions normales
```

---

## 📈 Performances Attendues

| Métrique | Objectif | Statut |
|----------|----------|--------|
| **Accuracy** | > 99% | 🎯 |
| **Precision** | > 99% | 🎯 |
| **Recall** | > 95% | 🎯 |
| **F1-Score** | > 97% | 🎯 |
| **ROC-AUC** | > 0.98 | 🎯 |
| **Temps réponse** | < 3s | 🎯 |

---

## 📊 Features Utilisées

```python
[
    "duration",           # Durée de la connexion (secondes)
    "protocol_type",      # 0=TCP, 1=UDP, 2=ICMP
    "bytes_sent",         # Octets envoyés
    "bytes_received",     # Octets reçus
    "nb_connections",     # Nombre de connexions
    "error_rate",         # Taux d'erreur (0-1)
    "same_ip_count",      # Nombre d'IPs identiques
    "port_number",        # Port utilisé (80, 443, 22, etc.)
    "bytes_ratio",        # Ratio sent/received
    "conn_per_second"     # Connexions par seconde
]
```

---

## 🎯 Menaces Détectées

### 1. **Normal** 🟢
Trafic légitime, pas de risque

### 2. **DoS/DDoS** 🔴 CRITIQUE
- Signature : 950+ connexions rapides
- Taux d'erreur élevé (> 0.78)
- Ports cibles : 80, 443, 53

### 3. **Intrusion** 🟠 ÉLEVÉ
- Ports suspects : 22, 23, 3389, 1433
- Trafic modéré mais persistant
- Tentatives d'escalade de privilèges

### 4. **Malware** 🟠 ÉLEVÉ
- Communication C&C (ports : 6667, 4444, 1337, 8888)
- Trafic bidirectionnel symétrique
- Multiples connexions simultanées

### 5. **Phishing** 🟡 MOYEN
- Gros volumes HTTP/HTTPS (2000-5000 bytes)
- Port 80/443
- Nombreuses connexions

### 6. **Brute-Force** 🔴 CRITIQUE
- 80+ tentatives rapides
- Taux d'erreur > 0.88
- Ports RDP (3389) ou SSH (22)

---

## 📡 API Endpoints

### Prédiction Simple
```bash
curl -X POST http://localhost:5000/api/predict \
  -H "Content-Type: application/json" \
  -d '{
    "duration": 2.5,
    "protocol_type": 0,
    "bytes_sent": 480,
    "bytes_received": 1100,
    "nb_connections": 4,
    "error_rate": 0.02,
    "same_ip_count": 2,
    "port_number": 443,
    "bytes_ratio": 0.44,
    "conn_per_second": 1.6
  }'
```

**Réponse :**
```json
{
  "threat": "Normal",
  "confidence": 0.9876,
  "severity": "none",
  "is_anomaly": false,
  "anomaly_score": -0.1234,
  "timestamp": "2024-11-05T14:30:00Z"
}
```

### Prédictions en Batch
```bash
curl -X POST http://localhost:5000/api/predict-batch \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {"duration": 2.5, "protocol_type": 0, ...},
      {"duration": 0.03, "protocol_type": 0, ...}
    ]
  }'
```

---

## 🧪 Tests

```bash
# Lancer tous les tests
pytest tests/ -v

# Test spécifique
pytest tests/test_threat_detector.py -v

# Avec couverture de code
pytest tests/ --cov=src --cov-report=html
```

---

## 📝 Configuration

Voir `config.yaml` pour :
- Chemins de données
- Paramètres du modèle
- Seuils de détection
- Configuration du dashboard

---

## 📚 Références Techniques

### Windows Event IDs
- [Microsoft Event ID Reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-events)
- [Brute Force Detection](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logon-events)

### Frameworks ML
- **scikit-learn** : Modèles classiques
- **XGBoost** : Boosting gradient
- **Dash** : Dashboard web
- **Flask** : API REST

---

## 📞 Support

Pour les questions ou les issues :
https://github.com/imaneoujoua/threat-detection-aiwindows-log-analyzer/issues

---

## 👨‍💻 Auteur

**Imane Oujoua**
- GitHub: [@imaneoujoua](https://github.com/imaneoujoua)
- Année universitaire : 2025-2026

---

## 📄 Licence

Ce projet est sous licence MIT. Voir `LICENSE` pour plus de détails.

---

**🎉 CyberShield AI - Protéger votre réseau avec l'IA**
