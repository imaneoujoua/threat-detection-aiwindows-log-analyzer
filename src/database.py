import sqlite3
from datetime import datetime

class AlertDatabase:

    def __init__(self, db_name="alerts.db"):
        self.conn = sqlite3.connect(db_name)
        self.create_table()

    def create_table(self):
        cursor = self.conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            threat_type TEXT,
            confidence REAL
        )
        """)

        self.conn.commit()

    def add_alert(self, threat_type, confidence):
        cursor = self.conn.cursor()

        cursor.execute("""
        INSERT INTO alerts(timestamp, threat_type, confidence)
        VALUES (?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            threat_type,
            confidence
        ))

        self.conn.commit()

    def get_alerts(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM alerts")
        return cursor.fetchall()
