from app import db
from datetime import datetime
import json

class IPKeyMapping(db.Model):
    """Store RSA key pairs for each IP address"""
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    public_key_pem = db.Column(db.Text, nullable=False)
    private_key_pem = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<IPKeyMapping {self.ip_address}>'

class UploadSession(db.Model):
    """Track file upload sessions"""
    id = db.Column(db.Integer, primary_key=True)
    sender_ip = db.Column(db.String(45), nullable=False)
    receiver_ip = db.Column(db.String(45), nullable=False)
    session_token = db.Column(db.String(64), unique=True, nullable=False)
    filename = db.Column(db.String(255))
    file_hash = db.Column(db.String(128))
    file_size = db.Column(db.Integer)
    file_metadata = db.Column(db.Text)
    filepath = db.Column(db.String(512))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    downloaded_at = db.Column(db.DateTime)
    
    def set_metadata(self, metadata_dict):
        self.file_metadata = json.dumps(metadata_dict)
    
    def get_metadata(self):
        return json.loads(self.file_metadata) if self.file_metadata else {}
    
    def update_status(self, new_status):
        """Update the status and updated_at timestamp"""
        if self.status != new_status:
            self.status = new_status
            self.updated_at = datetime.utcnow()
            return True
        return False
        
    def __repr__(self):
        return f'<UploadSession {self.session_token}>'

class Host(db.Model):
    """Store information about recipient hosts"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    description = db.Column(db.Text)
    public_key = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(45))
    
    def __repr__(self):
        return f'<Host {self.name} ({self.ip_address})>'
