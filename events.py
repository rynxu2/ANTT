import logging
from datetime import datetime
from app import socketio, db

def notify_new_host(host_data):
    """Emit event when a new host is created"""

    host_dict = {
        'id': host_data.id,
        'name': host_data.name,
        'ip_address': host_data.ip_address,
        'description': host_data.description,
        'created_by': host_data.created_by,
        'created_at': host_data.created_at.isoformat(),
        'has_keys': host_data.has_keys,
    }
    socketio.emit('new_host', host_dict, namespace='/', to=None)
    logging.info(f"Emitted new_host event: {host_dict}")

def notify_host_deleted(host_id):
    """Emit event when a host is deleted"""
    socketio.emit('host_deleted', {'id': host_id}, namespace='/', to=None)
    logging.info(f"Emitted host_deleted event for host ID: {host_id}")

def notify_action_start(client_ip, action):
    """Notify client that an action is starting"""
    try:
        socketio.emit('action_start', {'action': action}, room=client_ip, namespace='/')
        logging.info(f"Emitted action_start for {action} to {client_ip}")
    except Exception as e:
        logging.error(f"Error sending action_start for {action}: {str(e)}")

def notify_action_end(client_ip, action, success=True, error_message=None):
    """Notify client that an action has completed"""
    try:
        data = {
            'action': action,
            'success': success
        }
        if error_message:
            data['error'] = error_message
        
        socketio.emit('action_end', data, room=client_ip, namespace='/')
        logging.info(f"Emitted action_end for {action} to {client_ip}")
    except Exception as e:
        logging.error(f"Error sending action_end for {action}: {str(e)}")

def notify_new_file(file_data):
    """Emit event when a new file is uploaded"""
    try:
        file_dict = {
            'id': file_data.id,
            'session_token': file_data.session_token,
            'filename': file_data.filename,
            'file_size': file_data.file_size,
            'sender_ip': file_data.sender_ip,
            'receiver_ip': file_data.receiver_ip,
            'status': file_data.status,
            'created_at': file_data.created_at.isoformat(),
            'host_id': file_data.host_id if hasattr(file_data, 'host_id') else None,
        }
        
        logging.info(f"Emitting new_file event to receiver {file_data.receiver_ip}")
        socketio.emit('new_file', file_dict, room=file_data.receiver_ip, namespace='/')
        logging.info(f"New file event emitted successfully")
        
    except Exception as e:
        logging.error(f"Error in notify_new_file: {str(e)}")

def notify_status_change(session_data):
    """Emit event when a file's status changes (only to host/receiver)"""
    if not session_data:
        logging.error("notify_status_change called with invalid session_data")
        return

    if not hasattr(session_data, 'session_token') or not session_data.session_token:
        logging.error("Session data missing session_token")
        return

    try:
        if not session_data.updated_at:
            session_data.updated_at = datetime.utcnow()
            db.session.commit()

        client_ips = [ip for ip in [session_data.sender_ip, session_data.receiver_ip] if ip]
        if not client_ips:
            logging.error("No valid client IPs found in session data")
            return
            
        for client_ip in client_ips:
            print(f"Notifying client {client_ip} about status change for session {session_data.session_token}")
            try:
                notify_action_start(client_ip, 'status-update')
                
                status_dict = {
                    'session_token': session_data.session_token,
                    'status': session_data.status,
                    'updated_at': session_data.updated_at.isoformat() if hasattr(session_data, 'updated_at') and session_data.updated_at else datetime.utcnow().isoformat(),
                    'error_message': getattr(session_data, 'error_message', None)
                }
                
                logging.info(f"Emitting status_change to {client_ip} for session {session_data.session_token}")
                socketio.emit('status_change', status_dict, room=client_ip, namespace='/')
                logging.info(f"Successfully emitted status_change event to {client_ip}: {status_dict}")
                
                notify_action_end(client_ip, 'status-update')
                
            except Exception as client_error:
                logging.error(f"Error notifying client {client_ip}: {str(client_error)}")
                notify_action_end(client_ip, 'status-update', success=False, error_message=str(client_error))

    except Exception as e:
        logging.error(f"Error in notify_status_change: {str(e)}")
        try:
            notify_action_end(client_ip, 'status-update', success=False, error_message=str(e))
        except:
            pass

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
    
def notify_new_join_request(request):
    """Notify host owner about new join request"""
    request_dict = {
        'request_id': request.id,
        'sender_ip': request.sender_ip,
        'message': request.message,
        'created_at': request.created_at.strftime('%Y-%m-%d %H:%M')
    }
    print(f"Emitting new_join_request for request ID {request.id} to host {request.host_owner_ip}")
    socketio.emit('new_join_request', request_dict, room=request.host_owner_ip, namespace='/')

def notify_request_approved(request):
    """Notify sender that their request was approved"""
    socketio.emit('request_approved', {
        'request_id': request.id,
        'host_id': request.host_id,
        'response_message': request.response_message,
        'approved_at': request.approved_at.strftime('%Y-%m-%d %H:%M') if request.approved_at else None
    }, room=request.sender_ip, namespace='/')

def notify_request_rejected(request):
    """Notify sender that their request was rejected"""
    socketio.emit('request_rejected', {
        'request_id': request.id,
        'host_id': request.host_id
    }, room=request.sender_ip, namespace='/')

def notify_access_revoked(request):
    """Notify sender that their access was revoked"""
    socketio.emit('access_revoked', {
        'request_id': request.id,
        'host_id': request.host_id
    }, room=request.sender_ip, namespace='/')
