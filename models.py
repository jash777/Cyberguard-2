from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

db = SQLAlchemy()

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)
    status = db.Column(db.String(20), default='Unknown')
    last_check = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'ip_address': self.ip_address,
            'status': self.status,
            'last_check': self.last_check.isoformat() if self.last_check else None
        }

class FirewallRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    table = db.Column(db.String(20), nullable=False)
    chain = db.Column(db.String(20), nullable=False)
    rule = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'table': self.table,
            'chain': self.chain,
            'rule': self.rule
        }

def init_db(app):
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'cyberguard.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

    with app.app_context():
        db.create_all()