"""
Database models for email security threat logs and email scan results.

Provides SQLAlchemy ORM mappings for recording threat events, malicious URLs,
risk scores, geolocation metadata, and forensic analysis outputs.
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class ThreatLog(db.Model):
    __tablename__ = 'threat_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    url = db.Column(db.String(500))
    status = db.Column(db.String(50))
    flagged_reason = db.Column(db.String(200))
    category = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    details = db.Column(db.Text)
    risk_score = db.Column(db.Integer, default=0)
    geo_country = db.Column(db.String(10))
    geo_city = db.Column(db.String(100))

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'url': self.url,
            'status': self.status,
            'flagged_reason': self.flagged_reason,
            'category': self.category,
            'severity': self.severity,
            'risk_score': self.risk_score,
            'geo_country': self.geo_country,
            'geo_city': self.geo_city,
        }


class EmailScanResult(db.Model):
    __tablename__ = 'email_scan_results'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    email_id = db.Column(db.String(100))
    ml_prediction = db.Column(db.String(20))
    ml_confidence = db.Column(db.Float)
    risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(20))
    forensic_trust_score = db.Column(db.Integer)
    geo_country = db.Column(db.String(10))
    origin_ip = db.Column(db.String(45))
    full_result = db.Column(db.Text)  # JSON blob

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'email_id': self.email_id,
            'ml_prediction': self.ml_prediction,
            'ml_confidence': self.ml_confidence,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'forensic_trust_score': self.forensic_trust_score,
            'geo_country': self.geo_country,
            'origin_ip': self.origin_ip,
        }
