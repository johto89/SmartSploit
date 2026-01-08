from app import db
from datetime import datetime

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False)
    target_address = db.Column(db.String(42), nullable=False)
    exploit_module = db.Column(db.String(128), nullable=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ExploitResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), nullable=False)
    result_status = db.Column(db.String(20), nullable=False)
    data = db.Column(db.Text)
    execution_time = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class VulnerabilityTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(42), unique=True, nullable=False)
    network = db.Column(db.String(20), nullable=False)
    vulnerability_score = db.Column(db.Float, default=0.0)
    vulnerabilities = db.Column(db.Text)  # JSON string of detected vulnerabilities
    last_scanned = db.Column(db.DateTime, default=datetime.utcnow)
    balance = db.Column(db.String(32))

class FrameworkStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    active_modules = db.Column(db.Integer, default=0)
    successful_exploits = db.Column(db.Integer, default=0)
    active_sessions = db.Column(db.Integer, default=0)
    high_risk_contracts = db.Column(db.Integer, default=0)
    medium_risk_contracts = db.Column(db.Integer, default=0)
    low_risk_contracts = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
