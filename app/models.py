from app.extension import db
from flask_login import UserMixin

class ThreatIP(db.Model):
    __tablename__ = 'threat_ips'
    ip_address = db.Column(db.String, primary_key=True)
    source = db.Column(db.String)
    confidence_score = db.Column(db.Integer)
    abuse_categories = db.Column(db.String)
    country = db.Column(db.String)
    city = db.Column(db.String)
    isp = db.Column(db.String)
    asn = db.Column(db.String)
    shodan_ports = db.Column(db.String)
    last_seen = db.Column(db.DateTime)

class Indicator(db.Model):
    __tablename__ = 'related_indicators'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String)
    indicator = db.Column(db.String)
    indicator_type = db.Column(db.String)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)



class ClientUser(UserMixin, db.Model):
    __tablename__ = 'client_users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
