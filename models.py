from app import db
from datetime import datetime
import json
import base64

class IPUserKeyMapping(db.Model):
    """Store RSA key pairs for each IP address"""
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    has_keys = db.Column(db.Boolean, default=False, nullable=False)
    public_key = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<IPKeyMapping {self.ip_address}>'

class IPHostKeyMapping(db.Model):
    """Store RSA key pairs for each IP address"""
    id = db.Column(db.Integer, primary_key=True)
    host_ip = db.Column(db.String(45), nullable=False)
    host_name = db.Column(db.String(100), nullable=False)
    has_keys = db.Column(db.Boolean, default=False, nullable=False)
    public_key = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<IPKeyMapping {self.host_ip} - ({self.host_name})>'

class UploadSession(db.Model):
    """Track file upload sessions"""
    id = db.Column(db.Integer, primary_key=True)
    sender_ip = db.Column(db.String(45), nullable=False)
    receiver_ip = db.Column(db.String(45), nullable=False)
    receiver_name = db.Column(db.String(100), nullable=False)
    session_token = db.Column(db.String(64), unique=True, nullable=False)
    filename = db.Column(db.String(255))
    file_hash = db.Column(db.String(128))
    file_size = db.Column(db.Integer)
    file_metadata = db.Column(db.Text)
    filepath = db.Column(db.String(512))
    drive_file_id = db.Column(db.String(100), nullable=True)
    drive_link = db.Column(db.String(512), nullable=True)
    source_type = db.Column(db.String(10))
    status = db.Column(db.String(20), default='pending')
    fail_step = db.Column(db.String(50))
    error_message = db.Column(db.Text)
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

    def update_fail_info(self, fail_step, error_message):
        """Update failure information and status"""
        try:
            self.fail_step = fail_step
            self.error_message = error_message
            self.status = 'failed'
            self.updated_at = datetime.utcnow()
            return True
        except:
            return False
    
    def cache_session_key(self, session_key):
        """Cache session key temporarily in metadata"""
        metadata = self.get_metadata()
        metadata['cached_session_key'] = base64.b64encode(session_key).decode('utf-8')
        self.set_metadata(metadata)

    def get_cached_session_key(self):
        """Get cached session key from metadata"""
        metadata = self.get_metadata()
        if 'cached_session_key' not in metadata:
            raise Exception('No cached session key found')
        return base64.b64decode(metadata['cached_session_key'].encode('utf-8'))
        
    def __repr__(self):
        return f'<UploadSession {self.session_token}>'

class Host(db.Model):
    """Store information about recipient hosts"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    description = db.Column(db.Text)
    has_keys = db.Column(db.Boolean, default=False, nullable=False)
    public_key = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(45))
    
    # Add unique constraint on name and ip_address combination
    __table_args__ = (
        db.UniqueConstraint('name', 'ip_address', name='uix_host_name_ip'),
    )
    
    def __repr__(self):
        return f'<Host {self.name} ({self.ip_address})>'

class HostJoinRequest(db.Model):
    """Model for host join requests"""
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'), nullable=False)
    host_name = db.Column(db.String(100), nullable=False)
    sender_ip = db.Column(db.String(45), nullable=False)
    host_owner_ip = db.Column(db.String(45), nullable=False)
    message = db.Column(db.String(255))
    response_message = db.Column(db.String(255))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime)
    rejected_at = db.Column(db.DateTime)
    revoked_at = db.Column(db.DateTime)

    host = db.relationship('Host', backref=db.backref('join_requests', lazy=True))