```python
import sqlite3
from datetime import datetime


class AlertDatabase:

    def __init__(self, db_name="alerts.db"):
        self.db_name = db_name
        self.create_tables()

    def get_connection(self):
        return sqlite3.connect(self.db_name)

    def create_tables(self):

        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_source TEXT,
            attack_type TEXT,
            severity TEXT,
            confidence REAL,
            bytes_sent REAL,
            nb_connections INTEGER,
            is_anomaly INTEGER,
            details TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS model_metrics(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            accuracy REAL,
            precision REAL,
            recall REAL,
            f1_score REAL,
            roc_auc REAL,
            notes TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS windows_threats(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            threat_type TEXT,
            user_target TEXT,
            severity TEXT,
            severity_score REAL,
            details TEXT
        )
        """)

        conn.commit()
        conn.close()

    def insert_network_alert(
        self,
        ip_source,
        attack_type,
        severity,
        confidence,
        bytes_sent=None,
        nb_connections=None,
        is_anomaly=False,
        details=""
    ):

        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO network_alerts(
            timestamp,
            ip_source,
            attack_type,
            severity,
            confidence,
            bytes_sent,
            nb_connections,
            is_anomaly,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip_source,
            attack_type,
            severity,
            confidence,
            bytes_sent,
            nb_connections,
            int(is_anomaly),
            details
        ))

        conn.commit()
        conn.close()

    def insert_model_metrics(
        self,
        accuracy,
        precision,
        recall,
        f1_score,
        roc_auc=0,
        notes=""
    ):

        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO model_metrics(
            timestamp,
            accuracy,
            precision,
            recall,
            f1_score,
            roc_auc,
            notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            accuracy,
            precision,
            recall,
            f1_score,
            roc_auc,
            notes
        ))

        conn.commit()
        conn.close()

    def get_network_alerts(
        self,
        limit=100,
        attack_type=None
    ):

        conn = self.get_connection()
        cursor = conn.cursor()

        if attack_type:

            cursor.execute("""
            SELECT *
            FROM network_alerts
            WHERE attack_type=?
            ORDER BY id DESC
            LIMIT ?
            """, (attack_type, limit))

        else:

            cursor.execute("""
            SELECT *
            FROM network_alerts
            ORDER BY id DESC
            LIMIT ?
            """, (limit,))

        data = cursor.fetchall()

        conn.close()

        return data

    def get_windows_threats(
        self,
        limit=100,
        threat_type=None
    ):

        conn = self.get_connection()
        cursor = conn.cursor()

        if threat_type:

            cursor.execute("""
            SELECT *
            FROM windows_threats
            WHERE threat_type=?
            ORDER BY id DESC
            LIMIT ?
            """, (threat_type, limit))

        else:

            cursor.execute("""
            SELECT *
            FROM windows_threats
            ORDER BY id DESC
            LIMIT ?
            """, (limit,))

        data = cursor.fetchall()

        conn.close()

        return data

    def get_statistics(self):

        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM network_alerts"
        )
        total_alerts = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM windows_threats"
        )
        total_windows_threats = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM model_metrics"
        )
        total_models = cursor.fetchone()[0]

        conn.close()

        return {
            "network_alerts": total_alerts,
            "windows_threats": total_windows_threats,
            "model_metrics": total_models
        }
```
