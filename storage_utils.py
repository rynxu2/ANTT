import os
import shutil
from pathlib import Path
from datetime import datetime
import hashlib
import secrets
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secure_uploads')
TEMP_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'temp_uploads')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(TEMP_FOLDER, exist_ok=True)

def generate_secure_path(filename, session_token):
    """Generate a secure path for file storage using session token"""
    today = datetime.now().strftime('%Y/%m/%d')
    secure_name = secure_filename(filename)
    
    session_path = os.path.join(UPLOAD_FOLDER, today, session_token[:2], session_token[2:4])
    os.makedirs(session_path, exist_ok=True)
    
    return os.path.join(session_path, secure_name)

def store_temp_file(file_storage):
    """Store an uploaded file temporarily and return temp path and hash"""
    try:
        temp_token = secrets.token_hex(16)
        secure_name = secure_filename(file_storage.filename)
        temp_path = os.path.join(TEMP_FOLDER, f"{temp_token}_{secure_name}")
        
        os.makedirs(TEMP_FOLDER, exist_ok=True)
        
        sha512_hash = hashlib.sha512()
        
        file_storage.save(temp_path)
        
        with open(temp_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha512_hash.update(chunk)
        
        return temp_path, sha512_hash.hexdigest()
        
    except Exception as e:
        if 'temp_path' in locals() and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass
        raise Exception(f"Failed to store temporary file: {str(e)}")

def move_temp_to_permanent(temp_path, session_token, filename):
    """Move a temporary file to its permanent storage location"""
    try:
        if not os.path.exists(temp_path):
            raise Exception("Temporary file does not exist")
            
        perm_path = generate_secure_path(filename, session_token)
        
        os.makedirs(os.path.dirname(perm_path), exist_ok=True)
        
        shutil.move(temp_path, perm_path)
        
        return perm_path
    except Exception as e:
        raise Exception(f"Failed to move file to permanent storage: {str(e)}")

def cleanup_temp_files():
    """Clean up temporary files older than 1 hour"""
    current_time = datetime.now().timestamp()
    for temp_file in Path(TEMP_FOLDER).glob('*'):
        if current_time - temp_file.stat().st_mtime > 3600:
            try:
                temp_file.unlink()
            except OSError:
                pass
