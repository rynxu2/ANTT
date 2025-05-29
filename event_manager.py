from app import socketio
from datetime import datetime

def emit_status_change(file):
    """
    Emit a status change event to both sender and receiver via Socket.IO
    """
    data = {
        'file_id': file.id,
        'session_token': file.session_token,
        'status': file.status,
        'filename': file.filename,
        'timestamp': datetime.utcnow().isoformat(),
    }
    
    socketio.emit('status_change', data, room=file.sender_ip)
    socketio.emit('status_change', data, room=file.receiver_ip)

def emit_file_received(file):
    """
    Emit a new file notification to receiver via Socket.IO
    """
    data = {
        'id': file.id,
        'session_token': file.session_token,
        'filename': file.filename,
        'sender_ip': file.sender_ip,
        'file_size': file.file_size,
        'status': file.status,
        'created_at': file.created_at.isoformat(),
        'file_metadata': file.get_metadata()
    }
    
    socketio.emit('new_file', data, room=file.receiver_ip)

def join_room(client_ip):
    """
    Join a room based on client IP for realtime updates
    """
    from flask_socketio import join_room as socketio_join_room
    socketio_join_room(client_ip)

def leave_room(client_ip):
    """
    Leave a room based on client IP
    """
    from flask_socketio import leave_room as socketio_leave_room
    socketio_leave_room(client_ip)