"""
╔══════════════════════════════════════════════════════════════════╗
║     CyberShield AI v2.0 — Détection de Cyberattaques           ║
║     Département Génie Informatique — Filière CDL                ║
║     Année universitaire 2025-2026                               ║
╚══════════════════════════════════════════════════════════════════╝

Fonctionnalités v2 :
  - Analyse des vrais logs Windows (Event ID)
  - Détection brute-force sur logs réels
  - Random Forest + Isolation Forest + XGBoost-style features
  - Score de risque par utilisateur et par IP
  - Export JSON des résultats pour le dashboard
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, f1_score, recall_score, precision_score, roc_auc_score
)
from sklearn.pipeline import Pipeline
import pickle, json, os, sqlite3, time, random
from datetime import datetime, timedelta
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

# ─── CONFIGURATION ────────────────────────────────────────────────────────────
CONFIG = {
    "n_estimators": 200,
    "max_depth": 15,
    "min_samples_split": 4,
    "class_weight": "balanced",
    "random_state": 42,
    "test_size": 0.2,
    "n_normal": 3000,
    "n_attacks": 2200,
    "cv_folds": 5,
}

LABELS      = {0: "Normal", 1: "DoS/DDoS", 2: "Intrusion", 3: "Malware", 4: "Phishing", 5: "BruteForce"}
SEVERITY    = {"Normal": "none", "DoS/DDoS": "critical", "Intrusion": "high",
               "Malware": "high", "Phishing": "medium", "BruteForce": "critical"}
COLORS_TERM = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[33m",
               "none": "\033[92m", "reset": "\033[0m", "cyan": "\033[96m", "bold": "\033[1m"}

FEATURES = [
    "duration", "protocol_type", "bytes_sent", "bytes_received",
    "nb_connections", "error_rate", "same_ip_count", "port_number",
    "bytes_ratio", "conn_per_second"  # nouvelles features v2
]

WINDOWS_EVENT_THREATS = {
    4625: {"name": "Echec connexion",    "risk": 3, "category": "BruteForce"},
    4616: {"name": "Heure modifiee",     "risk": 4, "category": "Tampering"},
    4672: {"name": "Privilege eleve",    "risk": 2, "category": "Privilege"},
    4720: {"name": "Compte cree",        "risk": 3, "category": "Persistence"},
    4722: {"name": "Compte active",      "risk": 2, "category": "Persistence"},
    4732: {"name": "Groupe modifie",     "risk": 3, "category": "Persistence"},
    4738: {"name": "Compte modifie",     "risk": 2, "category": "Recon"},
    4798: {"name": "Enum groupes",       "risk": 3, "category": "Recon"},
    4799: {"name": "Enum membres",       "risk": 3, "category": "Recon"},
    5379: {"name": "Credentials lus",   "risk": 5, "category": "Credential"},
    5382: {"name": "Vault lu",           "risk": 5, "category": "Credential"},
    4624: {"name": "Connexion OK",       "risk": 0, "category": "Normal"},
    4634: {"name": "Deconnexion",        "risk": 0, "category": "Normal"},
}

def c(text, color):
    return f"{COLORS_TERM.get(color,'')}{text}{COLORS_TERM['reset']}"


# ══════════════════════════════════════════════════════════════════
#  MODULE 1 — ANALYSEUR DE LOGS WINDOWS RÉELS
# ══════════════════════════════════════════════════════════════════
class WindowsLogAnalyzer:
    """
    Analyse des vrais logs Windows Event Log (CSV).
    Détecte : brute-force, escalade de privilèges, reconnaissance,
               vol de credentials, persistance.
    """

    def __init__(self):
        self.alerts = []
        self.user_risk_scores = defaultdict(float)
        self.ip_risk_scores   = defaultdict(float)

    def load_and_analyze(self, csv_path):
        """Charge le CSV et lance l'analyse complète."""
        print(f"  Chargement des logs : {csv_path}")
        df = pd.read_csv(csv_path)
        df['TimeCreated'] = pd.to_datetime(df['TimeCreated'], dayfirst=True, errors='coerce')
        df = df.sort_values('TimeCreated').reset_index(drop=True)

        print(f"  {len(df)} evenements charges. Analyse en cours...")

        results = {
            "total_events"     : len(df),
            "date_range"       : [str(df['TimeCreated'].min()), str(df['TimeCreated'].max())],
            "unique_users"     : df['UserName'].nunique(),
            "unique_ips"       : df['IpAddress'].nunique(),
            "events_by_type"   : {},
            "threats_detected" : [],
            "brute_force"      : self._detect_brute_force(df),
            "privilege_abuse"  : self._detect_privilege_abuse(df),
            "recon_activity"   : self._detect_recon(df),
            "credential_access": self._detect_credential_access(df),
            "risk_by_user"     : {},
            "risk_by_ip"       : {},
        }

        # Comptage par Event ID
        for eid, count in df['Id'].value_counts().items():
            info = WINDOWS_EVENT_THREATS.get(int(eid), {"name": f"Event {eid}", "risk": 0})
            results["events_by_type"][str(eid)] = {
                "name": info["name"], "count": int(count)
            }

        # Score de risque global par utilisateur
        for user, grp in df.groupby('UserName'):
            score = 0.0
            for eid, einfo in WINDOWS_EVENT_THREATS.items():
                cnt = len(grp[grp['Id'] == eid])
                score += cnt * einfo["risk"]
            if score > 0:
                results["risk_by_user"][str(user)] = round(score, 1)

        # Score de risque par IP
        for ip, grp in df.dropna(subset=['IpAddress']).groupby('IpAddress'):
            score = 0.0
            for eid, einfo in WINDOWS_EVENT_THREATS.items():
                cnt = len(grp[grp['Id'] == eid])
                score += cnt * einfo["risk"]
            if score > 0:
                results["risk_by_ip"][str(ip)] = round(score, 1)

        # Top menaces
        all_threats = (
            results["brute_force"]["incidents"] +
            results["privilege_abuse"]["incidents"] +
            results["recon_activity"]["incidents"] +
            results["credential_access"]["incidents"]
        )
        results["threats_detected"] = sorted(all_threats, key=lambda x: x.get("severity_score",0), reverse=True)[:20]

        return results

    def _detect_brute_force(self, df):
        """Détecte les attaques brute-force (> 5 échecs en < 5 min)."""
        fails = df[df['Id'] == 4625].copy()
        incidents = []

        for user, grp in fails.groupby('UserName'):
            grp = grp.sort_values('TimeCreated')
            window_fails = 0
            for i, row in grp.iterrows():
                # Compte les échecs dans les 5 dernières minutes
                t_start = row['TimeCreated'] - timedelta(minutes=5)
                recent = grp[(grp['TimeCreated'] >= t_start) & (grp['TimeCreated'] <= row['TimeCreated'])]
                if len(recent) >= 5:
                    window_fails = max(window_fails, len(recent))

            if window_fails >= 5:
                severity = "CRITIQUE" if window_fails >= 20 else "ELEVE"
                severity_score = window_fails * 3
                incidents.append({
                    "type": "BruteForce",
                    "target_user": str(user),
                    "total_fails": int(len(grp)),
                    "max_in_5min": int(window_fails),
                    "severity": severity,
                    "severity_score": severity_score,
                    "description": f"Brute-force sur '{user}': {len(grp)} echecs ({window_fails} en 5 min)"
                })

        return {
            "total_fails": int(len(fails)),
            "targeted_accounts": int(fails['UserName'].nunique()),
            "incidents": incidents
        }

    def _detect_privilege_abuse(self, df):
        """Détecte les escalades de privilèges suspectes."""
        priv = df[df['Id'] == 4672]
        incidents = []

        for user, grp in priv.groupby('UserName'):
            count = len(grp)
            if count > 50:  # Seuil suspect
                incidents.append({
                    "type": "PrivilegeAbuse",
                    "user": str(user),
                    "privilege_events": int(count),
                    "severity": "ELEVE" if count > 200 else "MOYEN",
                    "severity_score": count // 10,
                    "description": f"Utilisation anormale de privileges: {user} ({count} evenements)"
                })

        return {"total_privilege_events": int(len(priv)), "incidents": incidents}

    def _detect_recon(self, df):
        """Détecte la reconnaissance (enum utilisateurs/groupes)."""
        recon_ids = [4798, 4799]
        recon = df[df['Id'].isin(recon_ids)]
        incidents = []

        for user, grp in recon.groupby('UserName'):
            count = len(grp)
            if count > 10:
                incidents.append({
                    "type": "Reconnaissance",
                    "user": str(user),
                    "enum_count": int(count),
                    "severity": "ELEVE" if count > 50 else "MOYEN",
                    "severity_score": count // 5,
                    "description": f"Reconnaissance : {user} a enumere {count} comptes/groupes"
                })

        return {"total_recon_events": int(len(recon)), "incidents": incidents}

    def _detect_credential_access(self, df):
        """Détecte les accès aux credentials (Event 5379/5382)."""
        cred = df[df['Id'].isin([5379, 5382])]
        incidents = []

        for user, grp in cred.groupby('UserName'):
            count = len(grp)
            if count > 0:
                incidents.append({
                    "type": "CredentialAccess",
                    "user": str(user),
                    "access_count": int(count),
                    "severity": "CRITIQUE" if count > 20 else "ELEVE",
                    "severity_score": count * 5,
                    "description": f"Acces credential manager: {user} ({count} lectures)"
                })

        return {"total_cred_events": int(len(cred)), "incidents": incidents}


# ══════════════════════════════════════════════════════════════════
#  MODULE 2 — GÉNÉRATEUR DE DATASET ENRICHI
# ══════════════════════════════════════════════════════════════════
class DataGenerator:
    """
    Génère un dataset réseau synthétique enrichi avec des features v2.
    Inclut la classe BruteForce (absente en v1).
    """

    def __init__(self, seed=42):
        np.random.seed(seed)

    def generate(self, n_normal=3000, n_attacks=2200):
        records = []
        records += self._normal(n_normal)
        n_each = n_attacks // 5
        records += self._dos(n_each)
        records += self._intrusion(n_each)
        records += self._malware(n_each)
        records += self._phishing(n_each)
        records += self._bruteforce(n_attacks - 4*n_each)

        df = pd.DataFrame(records)
        df["bytes_sent"]     = df["bytes_sent"].clip(lower=0)
        df["bytes_received"] = df["bytes_received"].clip(lower=0)
        df["error_rate"]     = df["error_rate"].clip(0, 1)
        # Features dérivées
        df["bytes_ratio"]    = df["bytes_sent"] / (df["bytes_received"] + 1)
        df["conn_per_second"]= df["nb_connections"] / (df["duration"] + 0.01)
        return df.sample(frac=1, random_state=42).reset_index(drop=True)

    def _normal(self, n):
        return [{"duration": np.random.exponential(2), "protocol_type": np.random.choice([0,1,2],p=[0.6,0.3,0.1]),
                 "bytes_sent": np.random.normal(500,200), "bytes_received": np.random.normal(1200,400),
                 "nb_connections": np.random.poisson(5), "error_rate": np.random.beta(1,20),
                 "same_ip_count": np.random.poisson(2), "port_number": np.random.choice([80,443,22,8080],p=[0.4,0.4,0.1,0.1]), "label": 0} for _ in range(n)]

    def _dos(self, n):
        return [{"duration": np.random.exponential(0.05), "protocol_type": np.random.choice([0,2],p=[0.7,0.3]),
                 "bytes_sent": np.random.normal(45,8), "bytes_received": np.random.normal(90,15),
                 "nb_connections": np.random.poisson(700)+300, "error_rate": np.random.beta(6,2),
                 "same_ip_count": np.random.poisson(300)+150, "port_number": np.random.choice([80,443,53]), "label": 1} for _ in range(n)]

    def _intrusion(self, n):
        return [{"duration": np.random.exponential(18), "protocol_type": np.random.choice([0,1],p=[0.8,0.2]),
                 "bytes_sent": np.random.normal(300,100), "bytes_received": np.random.normal(800,300),
                 "nb_connections": np.random.poisson(3), "error_rate": np.random.beta(3,5),
                 "same_ip_count": np.random.poisson(1), "port_number": np.random.choice([22,23,3389,1433]), "label": 2} for _ in range(n)]

    def _malware(self, n):
        return [{"duration": np.random.normal(30,5), "protocol_type": np.random.choice([0,1],p=[0.5,0.5]),
                 "bytes_sent": np.random.normal(200,50), "bytes_received": np.random.normal(200,50),
                 "nb_connections": np.random.poisson(10), "error_rate": np.random.beta(2,8),
                 "same_ip_count": np.random.poisson(8), "port_number": np.random.choice([6667,4444,1337,8888]), "label": 3} for _ in range(n)]

    def _phishing(self, n):
        return [{"duration": np.random.exponential(5), "protocol_type": 0,
                 "bytes_sent": np.random.normal(2000,500), "bytes_received": np.random.normal(5000,1000),
                 "nb_connections": np.random.poisson(15), "error_rate": np.random.beta(1,10),
                 "same_ip_count": np.random.poisson(5), "port_number": np.random.choice([80,443],p=[0.7,0.3]), "label": 4} for _ in range(n)]

    def _bruteforce(self, n):
        """BruteForce : connexions rapides répétées, port 22/3389, beaucoup d'erreurs"""
        return [{"duration": np.random.exponential(0.2), "protocol_type": 0,
                 "bytes_sent": np.random.normal(150,30), "bytes_received": np.random.normal(100,20),
                 "nb_connections": np.random.poisson(80)+20, "error_rate": np.random.beta(7,1),
                 "same_ip_count": np.random.poisson(60)+20, "port_number": np.random.choice([22,3389,21,23]), "label": 5} for _ in range(n)]


# ══════════════════════════════════════════════════════════════════
#  MODULE 3 — DÉTECTEUR IA (Random Forest + Isolation Forest)
# ══════════════════════════════════════════════════════════════════
class CyberShieldDetector:
    """
    Système de détection hybride :
    - Random Forest pour classification supervisée (attaques connues)
    - Isolation Forest pour anomalies inconnues (zero-day)
    - Validation croisée stratifiée pour fiabilité
    """

    def __init__(self, config=CONFIG):
        self.config  = config
        self.clf     = None
        self.iso     = None
        self.scaler  = StandardScaler()
        self.trained = False

    def train(self, X_train, y_train, cross_validate=True):
        X_sc = self.scaler.fit_transform(X_train)

        # ── Random Forest ──────────────────────────────────────────
        print("  [RF] Entraînement Random Forest (200 arbres)...")
        self.clf = RandomForestClassifier(
            n_estimators=self.config["n_estimators"],
            max_depth=self.config["max_depth"],
            min_samples_split=self.config["min_samples_split"],
            class_weight=self.config["class_weight"],
            random_state=self.config["random_state"],
            n_jobs=-1
        )
        self.clf.fit(X_sc, y_train)

        # ── Isolation Forest ───────────────────────────────────────
        print("  [IF] Entraînement Isolation Forest sur trafic normal...")
        X_normal = X_sc[y_train == 0]
        self.iso = IsolationForest(n_estimators=120, contamination=0.08, random_state=42)
        self.iso.fit(X_normal)

        self.trained = True

        # ── Validation Croisée ─────────────────────────────────────
        if cross_validate:
            print(f"  [CV] Validation croisée {self.config['cv_folds']} folds...")
            cv_scores = cross_val_score(
                self.clf, X_sc, y_train,
                cv=StratifiedKFold(n_splits=self.config["cv_folds"], shuffle=True, random_state=42),
                scoring="f1_macro", n_jobs=-1
            )
            print(f"      F1 moyen (CV) : {cv_scores.mean()*100:.2f}% ± {cv_scores.std()*100:.2f}%")
            return cv_scores
        return None

    def predict(self, X):
        """Prédit la classe + score d'anomalie pour une connexion."""
        if not self.trained:
            raise RuntimeError("Modèle non entraîné.")
        X_sc   = self.scaler.transform(X)
        pred   = int(self.clf.predict(X_sc)[0])
        proba  = self.clf.predict_proba(X_sc)[0]
        iso_p  = self.iso.predict(X_sc)[0]
        iso_sc = float(self.iso.score_samples(X_sc)[0])

        label = LABELS[pred]
        return {
            "label"        : label,
            "confidence"   : round(float(proba[pred]), 4),
            "severity"     : SEVERITY[label],
            "is_anomaly"   : iso_p == -1,
            "anomaly_score": round(iso_sc, 4),
            "probabilities": {LABELS[i]: round(float(p), 4) for i, p in enumerate(proba)},
        }

    def evaluate(self, X_test, y_test):
        X_sc   = self.scaler.transform(X_test)
        y_pred = self.clf.predict(X_sc)
        y_prob = self.clf.predict_proba(X_sc)
        acc    = accuracy_score(y_test, y_pred)
        f1     = f1_score(y_test, y_pred, average="macro")
        rec    = recall_score(y_test, y_pred, average="macro")
        prec   = precision_score(y_test, y_pred, average="macro")

        print("\n" + "="*60)
        print(f"  Accuracy  : {acc*100:.2f}%")
        print(f"  F1 macro  : {f1*100:.2f}%")
        print(f"  Recall    : {rec*100:.2f}%")
        print(f"  Precision : {prec*100:.2f}%")
        print("="*60)
        print(classification_report(y_test, y_pred, target_names=[LABELS[i] for i in sorted(LABELS)]))

        return {"accuracy": round(acc,4), "f1": round(f1,4), "recall": round(rec,4), "precision": round(prec,4)}

    def feature_importance(self):
        if not self.trained: return {}
        return dict(sorted(zip(FEATURES, self.clf.feature_importances_), key=lambda x: x[1], reverse=True))

    def save(self, path="models"):
        os.makedirs(path, exist_ok=True)
        pickle.dump(self.clf,    open(f"{path}/rf_model.pkl",   "wb"))
        pickle.dump(self.iso,    open(f"{path}/iso_forest.pkl", "wb"))
        pickle.dump(self.scaler, open(f"{path}/scaler.pkl",     "wb"))
        print(f"  Modèles sauvegardés dans '{path}/'")

    @classmethod
    def load(cls, path="models"):
        d = cls()
        d.clf    = pickle.load(open(f"{path}/rf_model.pkl",   "rb"))
        d.iso    = pickle.load(open(f"{path}/iso_forest.pkl", "rb"))
        d.scaler = pickle.load(open(f"{path}/scaler.pkl",     "rb"))
        d.trained = True
        return d


# ══════════════════════════════════════════════════════════════════
#  MODULE 4 — BASE DE DONNÉES
# ══════════════════════════════════════════════════════════════════
class AlertDB:
    def __init__(self, path="database/cybersec.db"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path
        self._init()

    def _init(self):
        c = sqlite3.connect(self.path)
        c.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_source TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                bytes_sent REAL,
                nb_conn INTEGER,
                protocol TEXT,
                is_anomaly INTEGER DEFAULT 0,
                blocked INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS windows_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                user_target TEXT,
                severity TEXT NOT NULL,
                severity_score REAL,
                description TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ts ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_type ON alerts(attack_type);
        """)
        c.commit(); c.close()

    def insert_alert(self, ip, attack_type, severity, confidence, bytes_sent, nb_conn, protocol, is_anomaly=False):
        c = sqlite3.connect(self.path)
        c.execute("INSERT INTO alerts (timestamp,ip_source,attack_type,severity,confidence,bytes_sent,nb_conn,protocol,is_anomaly) VALUES (?,?,?,?,?,?,?,?,?)",
                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, attack_type, severity,
                   round(confidence,4), bytes_sent, nb_conn, protocol, int(is_anomaly)))
        c.commit(); c.close()

    def insert_windows_threat(self, threat):
        c = sqlite3.connect(self.path)
        c.execute("INSERT INTO windows_threats (timestamp,threat_type,user_target,severity,severity_score,description) VALUES (?,?,?,?,?,?)",
                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                   threat.get("type"), threat.get("target_user") or threat.get("user"),
                   threat.get("severity"), threat.get("severity_score"), threat.get("description")))
        c.commit(); c.close()

    def stats(self):
        c = sqlite3.connect(self.path)
        total  = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        bytype = dict(c.execute("SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type").fetchall())
        wthreats = c.execute("SELECT COUNT(*) FROM windows_threats").fetchone()[0]
        c.close()
        return {"total_network_alerts": total, "by_type": bytype, "windows_threats": wthreats}


# ══════════════════════════════════════════════════════════════════
#  MODULE 5 — PIPELINE PRINCIPAL
# ══════════════════════════════════════════════════════════════════
def run_pipeline(logs_csv=None):
    print(c("\n╔══════════════════════════════════════════════════════════╗", "cyan"))
    print(c("║   CyberShield AI v2.0 — Pipeline Complet                ║", "bold"))
    print(c("╚══════════════════════════════════════════════════════════╝\n", "cyan"))

    results = {}

    # ── ÉTAPE 1 : Analyse des logs Windows ────────────────────────
    if logs_csv and os.path.exists(logs_csv):
        print(c("[1/5] Analyse des logs Windows réels...", "bold"))
        analyzer = WindowsLogAnalyzer()
        log_results = analyzer.load_and_analyze(logs_csv)
        results["windows_analysis"] = log_results

        print(f"  Total événements  : {log_results['total_events']}")
        print(f"  Utilisateurs      : {log_results['unique_users']}")
        print(f"  Adresses IP       : {log_results['unique_ips']}")
        bf = log_results["brute_force"]
        print(f"  Échecs connexion  : {bf['total_fails']} (comptes ciblés : {bf['targeted_accounts']})")
        print(f"  Menaces détectées : {len(log_results['threats_detected'])}")

        if log_results["threats_detected"]:
            print(c("\n  TOP 3 MENACES CRITIQUES :", "bold"))
            for t in log_results["threats_detected"][:3]:
                sev_color = "critical" if "CRITIQUE" in t.get("severity","") else "high"
                print(f"  {c('●', sev_color)} [{t['type']}] {t['description']}")
    else:
        print(c("[1/5] Pas de logs Windows fournis — étape ignorée.", "medium"))
        log_results = None

    # ── ÉTAPE 2 : Génération du dataset ───────────────────────────
    print(c("\n[2/5] Génération du dataset réseau...", "bold"))
    gen = DataGenerator(seed=CONFIG["random_state"])
    df  = gen.generate(n_normal=CONFIG["n_normal"], n_attacks=CONFIG["n_attacks"])
    print(f"  {len(df)} enregistrements générés.")
    for lbl, cnt in df["label"].value_counts().sort_index().items():
        print(f"  — {LABELS[lbl]:15s} : {cnt}")

    # ── ÉTAPE 3 : Entraînement ────────────────────────────────────
    print(c("\n[3/5] Entraînement des modèles IA...", "bold"))
    X = df[FEATURES].values
    y = df["label"].values
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=CONFIG["test_size"], random_state=CONFIG["random_state"], stratify=y)
    print(f"  Train : {len(X_train)} | Test : {len(X_test)}")

    detector = CyberShieldDetector(CONFIG)
    cv_scores = detector.train(X_train, y_train, cross_validate=True)

    # ── ÉTAPE 4 : Évaluation ──────────────────────────────────────
    print(c("\n[4/5] Évaluation des performances...", "bold"))
    metrics = detector.evaluate(X_test, y_test)
    results["ml_metrics"] = metrics

    print(c("\n  Importance des features :", "bold"))
    for feat, imp in detector.feature_importance().items():
        bar = "█" * int(imp * 40)
        print(f"  {feat:22s} {bar} {imp*100:.1f}%")

    # ── ÉTAPE 5 : Sauvegarde et démonstration ─────────────────────
    print(c("\n[5/5] Sauvegarde + démonstration...", "bold"))
    detector.save("models")

    db = AlertDB("database/cybersec.db")
    if log_results:
        for threat in log_results["threats_detected"]:
            db.insert_windows_threat(threat)

    # Simulation de détections réseau
    test_cases = [
        ("Navigation normale",     [2.5,  0, 480,  1100, 4,   0.02, 2,  443, 0.44, 1.6]),
        ("Attaque DoS",            [0.03, 0,  42,    85, 950,  0.78,600,  80, 0.49,31667]),
        ("Intrusion SSH",          [22.0, 0, 300,   750,  2,   0.35,  1,  22, 0.40, 0.09]),
        ("Malware C&C",            [31.5, 1, 195,   200, 12,   0.15,  9,4444, 0.97, 0.38]),
        ("Phishing",               [4.8,  0,1950,  4900, 18,   0.08,  6,  80, 0.39, 3.75]),
        ("Brute-Force RDP",        [0.15, 0, 145,    95, 95,   0.88, 75,3389, 1.53,633.3]),
    ]

    print(c("\n  ANALYSE EN TEMPS RÉEL :", "bold"))
    print("  " + "─"*58)
    net_ips = [f"10.0.{random.randint(1,5)}.{random.randint(1,254)}" for _ in range(20)]

    for name, feat in test_cases:
        res  = detector.predict(np.array([feat]))
        sev  = res["severity"]
        conf = res["confidence"]
        anom = c("⚠ ANOMALIE", "high") if res["is_anomaly"] else c("✓ normal", "none")
        ip   = random.choice(net_ips)

        if sev == "none":
            verdict = c(f"✓ {res['label']}", "none")
        elif sev == "critical":
            verdict = c(f"🚨 {res['label']} — CRITIQUE", "critical")
        else:
            verdict = c(f"⚠  {res['label']} — {sev.upper()}", "high")

        print(f"  [{ip:14s}] {name:22s} → {verdict}")
        print(f"  {'':16s} Confiance: {conf*100:.1f}% | Isolation Forest: {anom}")

        if res["label"] != "Normal":
            db.insert_alert(ip, res["label"], sev, conf, feat[2], int(feat[4]), "TCP", res["is_anomaly"])

    # ── RÉSUMÉ ────────────────────────────────────────────────────
    db_stats = db.stats()
    print(c("\n╔══════════════════════════════════════════════════════════╗", "cyan"))
    print(c("║  RÉSUMÉ FINAL                                           ║", "bold"))
    print(c("╠══════════════════════════════════════════════════════════╣", "cyan"))
    print(f"║  Accuracy (RF)       : {metrics['accuracy']*100:6.2f}%                       ║")
    print(f"║  F1-Score (macro)    : {metrics['f1']*100:6.2f}%                       ║")
    print(f"║  Classes détectées   : 6 (Normal + 5 attaques)          ║")
    print(f"║  Alertes réseau (DB) : {db_stats['total_network_alerts']}                              ║")
    if log_results:
        print(f"║  Menaces Windows     : {db_stats['windows_threats']}                             ║")
        print(f"║  Brute-force détecté : {log_results['brute_force']['total_fails']} échecs connexion         ║")
    print(c("╚══════════════════════════════════════════════════════════╝\n", "cyan"))

    # Export JSON pour le dashboard
    export = {
        "generated_at": datetime.now().isoformat(),
        "ml_metrics": metrics,
        "cv_f1_mean": float(cv_scores.mean()) if cv_scores is not None else None,
        "db_stats": db_stats,
        "windows_analysis": log_results,
    }
    os.makedirs("reports", exist_ok=True)
    with open("reports/results.json", "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2, ensure_ascii=False, default=str)
    print(f"  Résultats exportés → reports/results.json")

    return detector, export


if __name__ == "__main__":
    import sys
    logs = sys.argv[1] if len(sys.argv) > 1 else None
    run_pipeline(logs_csv=logs)
