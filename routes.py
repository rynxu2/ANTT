import os
import json
import hashlib
import secrets
import base64
from datetime import datetime
from flask import request, render_template, jsonify, session, flash, redirect, url_for, send_file
from werkzeug.utils import secure_filename
from app import app, db
from models import IPKeyMapping, UploadSession, Host, HostJoinRequest
from crypto_utils import (
    generate_rsa_keypair, 
    encrypt_with_public_key, 
    decrypt_with_private_key,
    sign_data,
    verify_signature,
    encrypt_file_aes,
    decrypt_file_aes,
    generate_session_key,
    hash_file_with_iv,
    verify_file_hash
)
from storage_utils import (
    store_temp_file,
    move_temp_to_permanent,
    cleanup_temp_files,
    UPLOAD_FOLDER
)
from events import (
    notify_new_host, 
    notify_status_change, 
    notify_new_file, 
    notify_host_deleted, 
    notify_new_join_request, 
    notify_request_approved, 
    notify_request_rejected, 
    notify_access_revoked
)
import io
import ipaddress

# Constants for file status
FILE_STATUS = {
    'PENDING': 'pending',
    'VERIFIED': 'verified',
    'FAILED': 'failed',
    'DOWNLOADED': 'downloaded'
}

def get_client_ip():
    ip = None
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr

    try:
        return ipaddress.ip_address(ip).exploded
    except ValueError:
        return None

def ensure_sender_keys():
    """Ensure the current IP has RSA keys, create if not exists"""
    client_ip = get_client_ip()
    ip_mapping = IPKeyMapping.query.filter_by(ip_address=client_ip).first()
    
    if not ip_mapping:
        try:
            public_key_pem, private_key_pem = generate_rsa_keypair()
            
            new_mapping = IPKeyMapping(
                ip_address=client_ip,
                public_key_pem=public_key_pem,
                private_key_pem=private_key_pem
            )
            
            db.session.add(new_mapping)
            db.session.commit()
            return True
        except Exception as e:
            app.logger.error(f"Error generating keys for IP {client_ip}: {str(e)}")
            return False
    
    return True

@app.route('/')
def index():
    """Landing page to choose between Receiver and Sender mode"""
    return render_template('index.html')

@app.route('/receiver')
def receiver_dashboard():
    """Dashboard for receiver mode"""
    client_ip = get_client_ip()
    
    hosts = Host.query.filter_by(created_by=client_ip).all()
    
    host_ips = [host.ip_address for host in hosts]
    received_files = UploadSession.query.filter(
        UploadSession.receiver_ip.in_(host_ips)
    ).all()
    
    stats = {
        'active_hosts': len(hosts),
        'total_files': len(received_files),
        'total_size': sum(f.file_size for f in received_files if f.file_size),
        'last_activity': max((f.created_at for f in received_files), default=None)
    }
    
    return render_template('receiver_dashboard.html', stats=stats)

@app.route('/sender')
def sender_dashboard():
    """Dashboard for sender mode"""
    client_ip = get_client_ip()
    
    if not ensure_sender_keys():
        flash('Error generating RSA keys. Please try again.', 'error')
    
    all_transfers = UploadSession.query.filter_by(sender_ip=client_ip).all()
    
    recent_transfers = UploadSession.query.filter_by(
        sender_ip=client_ip
    ).order_by(
        UploadSession.created_at.desc()
    ).limit(5).all()
    
    stats = {
        'total_files': len(all_transfers),
        'total_size': sum(f.file_size for f in all_transfers if f.file_size),
        'completed': len([f for f in all_transfers if f.status in ['verified', 'downloaded']])
    }
    
    return render_template('sender_dashboard.html', 
                         recent_transfers=recent_transfers,
                         stats=stats)

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    """Generate RSA key pair for the client IP"""
    client_ip = get_client_ip()
    
    try:
        existing_mapping = IPKeyMapping.query.filter_by(ip_address=client_ip).first()
        if existing_mapping:
            return jsonify({
                'success': True,
                'message': 'Keys already exist for this IP',
                'public_key': existing_mapping.public_key_pem
            })
        
        public_key_pem, private_key_pem = generate_rsa_keypair()
        
        new_mapping = IPKeyMapping(
            ip_address=client_ip,
            public_key_pem=public_key_pem,
            private_key_pem=private_key_pem
        )
        
        db.session.add(new_mapping)
        db.session.commit()
        
        app.logger.info(f"Generated RSA keys for IP: {client_ip}")
        
        return jsonify({
            'success': True,
            'message': 'RSA key pair generated successfully',
            'public_key': public_key_pem
        })
        
    except Exception as e:
        app.logger.error(f"Error generating keys for IP {client_ip}: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error generating keys: {str(e)}'
        }), 500

@app.route('/sessions')
def view_sessions():
    """View all upload sessions for debugging"""
    sessions = UploadSession.query.order_by(UploadSession.created_at.desc()).all()
    return render_template('index.html', 
                         step='sessions',
                         sessions=sessions)

@app.route('/receiver_hosts')
def receiver_hosts():
    """List all hosts"""
    client_ip = get_client_ip()
    hosts = Host.query.all()
    return render_template('hosts.html', hosts=hosts, client_ip=client_ip)

@app.route('/hosts/add', methods=['POST'])
def add_host():
    """Add a new host"""
    client_ip = get_client_ip()
    name = request.form.get('name')
    description = request.form.get('description')
    
    existing_host = Host.query.filter_by(created_by=client_ip, name=name).first()
    if existing_host:
        flash('A host with this name already exists for your IP', 'error')
        return redirect(url_for('receiver_hosts'))
    
    ip_mapping = IPKeyMapping.query.filter_by(ip_address=client_ip).first()
    if not ip_mapping:
        try:
            public_key_pem, private_key_pem = generate_rsa_keypair()
            
            ip_mapping = IPKeyMapping(
                ip_address=client_ip,
                public_key_pem=public_key_pem,
                private_key_pem=private_key_pem
            )
            
            db.session.add(ip_mapping)
            db.session.commit()
            flash('RSA keys generated successfully', 'success')
        except Exception as e:
            flash(f'Error generating RSA keys: {str(e)}', 'error')
            return redirect(url_for('receiver_hosts'))
    
    new_host = Host(
        name=name,
        ip_address=client_ip,
        description=description,
        public_key=ip_mapping.public_key_pem,
        created_by=client_ip
    )
    
    try:
        db.session.add(new_host)
        db.session.commit()
        notify_new_host(new_host)
        flash('Host added successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding host: {str(e)}', 'error')
    
    return redirect(url_for('receiver_hosts'))

@app.route('/hosts/<int:host_id>/delete', methods=['POST'])
def delete_host(host_id):
    """Delete a host"""
    host = Host.query.get_or_404(host_id)
    client_ip = get_client_ip()
    
    if host.created_by != client_ip:
        flash('You can only delete hosts that you created', 'error')
        return redirect(url_for('receiver_hosts'))
    
    try:
        db.session.delete(host)
        db.session.commit()
        notify_host_deleted(host_id)
        flash('Host deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting host: {str(e)}', 'error')
    
    return redirect(url_for('receiver_hosts'))

@app.route('/sender_select_host')
def sender_select_host():
    """Display available hosts for selection"""
    if not ensure_sender_keys():
        flash('Error generating RSA keys. Please try again.', 'error')
        return redirect(url_for('sender_dashboard'))
    
    client_ip = get_client_ip()
    hosts = Host.query.all()
    
    # Lấy các yêu cầu tham gia host của người dùng hiện tại
    host_requests = {}
    join_requests = HostJoinRequest.query.filter_by(
        sender_ip=client_ip
    ).order_by(HostJoinRequest.created_at.desc()).all()
    
    # Tạo dictionary chứa status yêu cầu cho mỗi host
    for request in join_requests:
        # Chỉ lưu request mới nhất cho mỗi host
        if request.host_id not in host_requests:
            host_requests[request.host_id] = {
                'status': request.status,
                'created_at': request.created_at,
                'approved_at': request.approved_at,
                'rejected_at': request.rejected_at,
                'revoked_at': request.revoked_at,
                'message': request.message,
                'response_message': request.response_message
            }
    
    return render_template('select_host.html', 
                         hosts=hosts,
                         host_requests=host_requests)

@app.route('/select_host/<int:host_id>', methods=['POST'])
def select_upload_host(host_id):
    """Select a host for file upload"""
    host = Host.query.get_or_404(host_id)
    
    if not host.public_key:
        flash('Selected host does not have a public key available', 'error')
        return redirect(url_for('sender_select_host'))
    
    session['selected_host_id'] = host_id
    session['selected_host_name'] = host.name
    session['selected_host_ip'] = host.ip_address
    session['selected_host_public_key'] = host.public_key
    session['mode'] = 'sender'
    
    app.logger.info(f"Host selected - ID: {host_id}, Name: {host.name}, IP: {host.ip_address}")
    
    return redirect(url_for('sender_secure_upload'))

@app.route('/receiver_files')
def receiver_files():
    """Display files received by the user's hosts"""
    client_ip = get_client_ip()
    
    hosts = Host.query.filter_by(created_by=client_ip).all()
    
    selected_host_id = request.args.get('host_id', type=int)
    if selected_host_id:
        selected_host = Host.query.get_or_404(selected_host_id)
        if selected_host.created_by != client_ip:
            flash('Access denied', 'error')
            return redirect(url_for('receiver_files'))
        
        received_files = UploadSession.query.filter_by(
            receiver_ip=selected_host.ip_address
        ).order_by(UploadSession.created_at.desc()).all()
    else:
        host_ips = [host.ip_address for host in hosts]
        received_files = UploadSession.query.filter(
            UploadSession.receiver_ip.in_(host_ips)
        ).order_by(UploadSession.created_at.desc()).all()
    
    stats = {
        'total_files': len(received_files),
        'total_size': sum(f.file_size for f in received_files if f.file_size),
        'unique_senders': len(set(f.sender_ip for f in received_files)),
        'last_received': max((f.created_at for f in received_files), default=None)
    }
    
    return render_template('received_files.html',
                         hosts=hosts,
                         selected_host_id=selected_host_id,
                         received_files=received_files,
                         stats=stats)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle secure file upload"""
    app.logger.info("Starting file upload process")

    csrf_token = request.headers.get('X-CSRFToken')
    if not csrf_token:
        app.logger.error("CSRF token missing in headers")
        return jsonify({'error': 'CSRF token missing'}), 400

    if 'file' not in request.files:
        app.logger.error("No file found in request.files")
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        app.logger.error("Uploaded file has empty filename")
        return jsonify({'error': 'No selected file'}), 400

    app.logger.info(f"Processing file: {file.filename}")

    selected_host_id = session.get('selected_host_id')
    if not selected_host_id:
        app.logger.error("Session does not contain selected_host_id")
        return jsonify({'error': 'No host selected'}), 400

    host = Host.query.get(selected_host_id)
    if not host:
        app.logger.error(f"Host not found with ID: {selected_host_id}")
        return jsonify({'error': 'Invalid host'}), 400

    sender_ip = get_client_ip()
    app.logger.info(f"Sender IP: {sender_ip}")

    try:
        existing_file = UploadSession.query.filter_by(
            sender_ip=sender_ip,
            receiver_ip=host.ip_address,
            status=FILE_STATUS['PENDING']
        ).order_by(UploadSession.created_at.desc()).first()
    except Exception as e:
        app.logger.error(f"Database error while querying UploadSession: {str(e)}")
        return jsonify({'error': 'Server error querying uploads'}), 500
    print(11)
    if existing_file:
        if existing_file.status not in [FILE_STATUS['VERIFIED'], FILE_STATUS['FAILED']]:
            app.logger.warning(f"Duplicate upload attempt by {sender_ip} to host {host.ip_address}")
            return jsonify({
                'error': 'You already have an active file transfer to this host. Please wait for verification or mark it as failed before uploading a new file.',
                'status': existing_file.status,
                'session_token': existing_file.session_token
            }), 400

    temp_path = None
    encrypted_path = None

    try:
        sender_keys = IPKeyMapping.query.filter_by(ip_address=sender_ip).first()
        if not sender_keys:
            app.logger.error(f"No keys found for sender IP {sender_ip}")
            raise Exception("Sender keys not found")

        temp_path, file_hash = store_temp_file(file)
        app.logger.info(f"Temporary file stored at: {temp_path}")

        session_token = secrets.token_urlsafe(48)
        session_key = generate_session_key()

        file_metadata = {
            'filename': file.filename,
            'timestamp': datetime.utcnow().isoformat(),
            'sender_ip': sender_ip
        }

        try:
            metadata_bytes = json.dumps(file_metadata).encode('utf-8')
            metadata_signature = sign_data(metadata_bytes, sender_keys.private_key_pem)
        except Exception as e:
            app.logger.error(f"Signing metadata failed: {str(e)}")
            raise Exception("Metadata signing failed")

        try:
            with open(temp_path, 'rb') as f:
                file_data = f.read()
        except Exception as e:
            app.logger.error(f"Reading temp file failed: {str(e)}")
            raise Exception("Unable to read uploaded file")

        try:
            encrypted_session_key = encrypt_with_public_key(session_key, host.public_key)
        except Exception as e:
            app.logger.error(f"Encrypting session key failed: {str(e)}")
            raise Exception("File encryption failed: Unable to encrypt session key")

        try:
            encrypted_data, iv = encrypt_file_aes(file_data, session_key)
        except Exception as e:
            app.logger.error(f"AES encryption failed: {str(e)}")
            raise Exception("AES encryption failed")

        secured_hash = hash_file_with_iv(iv, encrypted_data)

        try:
            encrypted_path = move_temp_to_permanent(temp_path, session_token, file.filename)
        except Exception as e:
            app.logger.error(f"Moving encrypted file failed: {str(e)}")
            raise Exception("Error saving encrypted file")

        try:
            with open(encrypted_path, 'wb') as f:
                f.write(iv + encrypted_data)
        except Exception as e:
            app.logger.error(f"Writing encrypted data failed: {str(e)}")
            raise Exception("Saving encrypted file failed")

        upload_session = UploadSession(
            sender_ip=sender_ip,
            receiver_ip=host.ip_address,
            session_token=session_token,
            filename=file.filename,
            file_hash=secured_hash,
            file_size=len(file_data),
            filepath=encrypted_path,
            status=FILE_STATUS['PENDING']
        )

        try:
            metadata = {
                'iv': base64.b64encode(iv).decode('utf-8'),
                'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
                'metadata': file_metadata,
                'metadata_signature': base64.b64encode(metadata_signature).decode('utf-8')
            }
            app.logger.info(f"Setting metadata for upload session: {metadata}")
            upload_session.set_metadata(metadata)
        except Exception as e:
            app.logger.error(f"Storing metadata failed: {str(e)}")
            raise Exception("Failed to set metadata")

        db.session.add(upload_session)
        db.session.commit()
        app.logger.info(f"Upload session committed: {session_token}")

        try:
            notify_new_file(upload_session)
            app.logger.info(f"New file notification sent for session: {session_token}")
        except Exception as notify_error:
            app.logger.warning(f"Notification failed: {str(notify_error)}")

        return jsonify({
            'message': 'File uploaded successfully',
            'session_token': session_token,
            'file_hash': secured_hash,
            'metadata': {
                'iv': base64.b64encode(iv).decode('utf-8'),
                'public_key': host.public_key,
                'hash_type': 'SHA-512'
            }
        })

    except Exception as e:
        app.logger.error(f"Upload process failed: {str(e)}")

        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                app.logger.info(f"Temp file removed: {temp_path}")
            except Exception as cleanup_error:
                app.logger.warning(f"Failed to remove temp file: {cleanup_error}")

        if encrypted_path and os.path.exists(encrypted_path):
            try:
                os.remove(encrypted_path)
                app.logger.info(f"Encrypted file removed: {encrypted_path}")
            except Exception as cleanup_error:
                app.logger.warning(f"Failed to remove encrypted file: {cleanup_error}")

        try:
            db.session.rollback()
            app.logger.info("Database session rolled back")
        except Exception as db_error:
            app.logger.error(f"Database rollback failed: {db_error}")

        return jsonify({'error': str(e)}), 500

    finally:
        try:
            cleanup_temp_files()
            app.logger.info("Temporary files cleaned up")
        except Exception as cleanup_error:
            app.logger.warning(f"Error during temp cleanup: {cleanup_error}")


@app.route('/download/<session_token>')
def download_file(session_token):
    """Handle secure file download"""
    try:
        upload_session = UploadSession.query.filter_by(session_token=session_token).first()
        if not upload_session:
            return jsonify({'error': 'Invalid session token'}), 404
        
        if upload_session.status != FILE_STATUS['VERIFIED']:
            return jsonify({'error': 'File not verified'}), 400
        
        client_ip = get_client_ip()
        key_mapping = IPKeyMapping.query.filter_by(ip_address=client_ip).first()
        if not key_mapping:
            return jsonify({'error': 'Recipient keys not found'}), 404
        
        metadata = upload_session.get_metadata()
        iv = base64.b64decode(metadata['iv'])
        encrypted_session_key = base64.b64decode(metadata['encrypted_session_key'])
        
        session_key = decrypt_with_private_key(
            encrypted_session_key,
            key_mapping.private_key_pem
        )
        
        # Read the encrypted file which contains iv + ciphertext
        with open(upload_session.filepath, 'rb') as f:
            file_contents = f.read()
            
        # Extract IV (first 16 bytes) and ciphertext
        stored_iv = file_contents[:16]
        encrypted_data = file_contents[16:]
        
        # Verify the IV matches the one in metadata
        if stored_iv != iv:
            app.logger.error("IV mismatch between stored file and metadata")
            return jsonify({'error': 'IV verification failed'}), 400
            
        # Verify hash one final time before decryption
        if not verify_file_hash(stored_iv, encrypted_data, upload_session.file_hash):
            app.logger.error("File integrity check failed during download")
            return jsonify({'error': 'File integrity check failed'}), 400
            
        decrypted_data = decrypt_file_aes(encrypted_data, session_key, stored_iv)
        
        if hashlib.sha512(decrypted_data).hexdigest() != upload_session.file_hash:
            return jsonify({'error': 'File integrity check failed'}), 400
            
        try:
            file_stream = io.BytesIO(decrypted_data)
            
            upload_session.update_status(FILE_STATUS['DOWNLOADED'])
            upload_session.downloaded_at = datetime.utcnow()
            db.session.commit()
            
            notify_status_change(upload_session)
            
            app.logger.info(f"File download started: {upload_session.session_token}")
            
            try:
                notify_status_change(upload_session)
                app.logger.info(f"Download status change notification sent for session: {upload_session.session_token}")
            except Exception as notify_error:
                app.logger.error(f"Error sending download status notification: {str(notify_error)}")
            
            response = send_file(
                file_stream,
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=upload_session.filename
            )
            
            @response.call_on_close
            def on_close():
                try:
                    file_stream.close()
                except:
                    upload_session.status = FILE_STATUS['VERIFIED']
                    upload_session.downloaded_at = None
                    db.session.commit()
                    notify_status_change(upload_session)
            
            return response
            
        except Exception as e:
            db.session.rollback()
            upload_session.status = FILE_STATUS['VERIFIED']
            upload_session.downloaded_at = None
            db.session.commit()
            notify_status_change(upload_session)
            raise
        
    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/sender_secure_upload')
def sender_secure_upload():
    """Show the secure file upload page"""
    selected_host_id = session.get('selected_host_id')
    if not selected_host_id:
        flash('Please select a host first.', 'warning')
        return redirect(url_for('sender_select_host'))
    
    selected_host = Host.query.get(selected_host_id)
    if not selected_host:
        flash('Selected host not found.', 'error')
        return redirect(url_for('sender_select_host'))
    
    client_ip = get_client_ip()
    if not IPKeyMapping.query.filter_by(ip_address=client_ip).first():
        if not ensure_sender_keys():
            flash('Failed to generate sender keys.', 'error')
            return redirect(url_for('sender_dashboard'))
    
    return render_template('secure_upload.html', selected_host=selected_host)

@app.route('/verify_file/<session_token>', methods=['POST'])
def verify_file(session_token):
    """Verify a received file"""
    app.logger.info(f"Starting verification for session token: {session_token}")

    upload_session = UploadSession.query.filter_by(session_token=session_token).first()
    if not upload_session:
        app.logger.error(f"Upload session not found for token: {session_token}")
        return jsonify({'error': 'Invalid session token'}), 404

    client_ip = get_client_ip()
    app.logger.info(f"Client IP: {client_ip}")

    if upload_session.receiver_ip != client_ip:
        app.logger.error(f"Unauthorized IP: {client_ip} (expected: {upload_session.receiver_ip})")
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        key_mapping = IPKeyMapping.query.filter_by(ip_address=client_ip).first()
        if not key_mapping:
            app.logger.error(f"Recipient keys not found for IP: {client_ip}")
            return jsonify({'error': 'Recipient keys not found'}), 404

        sender_keys = IPKeyMapping.query.filter_by(ip_address=upload_session.sender_ip).first()
        if not sender_keys:
            app.logger.error(f"Sender keys not found for IP: {upload_session.sender_ip}")
            return jsonify({'error': 'Sender keys not found'}), 404

        try:
            metadata = upload_session.get_metadata()
            iv = base64.b64decode(metadata['iv'])
            encrypted_session_key = base64.b64decode(metadata['encrypted_session_key'])
            metadata_signature = base64.b64decode(metadata['metadata_signature'])
        except Exception as e:
            app.logger.error(f"Metadata decoding failed: {str(e)}")
            return jsonify({'error': 'Metadata decoding error'}), 400

        try:
            is_valid = verify_signature(
                json.dumps(metadata['metadata']).encode('utf-8'),
                metadata_signature,
                sender_keys.public_key_pem
            )
        except Exception as e:
            app.logger.error(f"Signature verification error: {str(e)}")
            return jsonify({'error': 'Signature verification failed'}), 400

        if not is_valid:
            app.logger.error("Invalid file signature (failed verification)")
            return jsonify({'error': 'Invalid file signature'}), 400

        if metadata['metadata']['sender_ip'] != upload_session.sender_ip:
            app.logger.error("Sender IP mismatch in metadata")
            return jsonify({'error': 'Sender IP verification failed'}), 400

        try:
            timestamp = datetime.fromisoformat(metadata['metadata']['timestamp'])
        except Exception as e:
            app.logger.error(f"Timestamp parsing failed: {str(e)}")
            return jsonify({'error': 'Invalid timestamp format'}), 400

        time_diff = datetime.utcnow() - timestamp
        if time_diff.total_seconds() > 1800:
            app.logger.error("Request expired - timestamp too old")
            return jsonify({'error': 'Request expired'}), 400

        try:
            session_key = decrypt_with_private_key(
                encrypted_session_key,
                key_mapping.private_key_pem
            )
        except Exception as e:
            app.logger.error(f"Failed to decrypt session key: {str(e)}")
            return jsonify({'error': 'Invalid session key'}), 400

        try:
            with open(upload_session.filepath, 'rb') as f:
                file_contents = f.read()
        except Exception as e:
            app.logger.error(f"Error reading encrypted file: {str(e)}")
            return jsonify({'error': 'File read error'}), 400

        stored_iv = file_contents[:16]
        encrypted_data = file_contents[16:]

        if stored_iv != iv:
            app.logger.error("IV mismatch between file and metadata")
            return jsonify({'error': 'IV verification failed'}), 400

        if not verify_file_hash(stored_iv, encrypted_data, upload_session.file_hash):
            app.logger.error("File hash does not match expected value")
            return jsonify({'error': 'File integrity check failed'}), 400

        try:
            decrypted_test = decrypt_file_aes(encrypted_data, session_key, stored_iv)
            app.logger.info(f"Decryption test passed for session: {session_token}")
        except Exception as e:
            app.logger.error(f"Test decryption failed: {str(e)}")
            return jsonify({'error': 'File decryption test failed'}), 400

        try:
            upload_session.update_status(FILE_STATUS['VERIFIED'])
            db.session.commit()
            app.logger.info(f"File verified and status updated: {session_token}")
        except Exception as e:
            app.logger.error(f"Database update failed: {str(e)}")
            return jsonify({'error': 'Database error during update'}), 500

        try:
            notify_status_change(upload_session)
            app.logger.info(f"Notification sent for verified file: {session_token}")
        except Exception as notify_error:
            app.logger.warning(f"Notification failed: {str(notify_error)}")

        return jsonify({
            'message': 'File verified successfully',
            'filename': upload_session.filename,
            'file_size': upload_session.file_size,
            'status': upload_session.status,
            'session_token': upload_session.session_token
        })

    except Exception as e:
        app.logger.error(f"Unexpected error in verification: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/transfer_status/<session_token>')
def transfer_status(session_token):
    """Get current status of a file transfer session"""
    app.logger.info(f"Checking status for session: {session_token}")
    
    upload_session = UploadSession.query.filter_by(session_token=session_token).first()
    if not upload_session:
        app.logger.error(f"Invalid session token: {session_token}")
        return jsonify({'error': 'Invalid session token'}), 404
    
    client_ip = get_client_ip()
    if upload_session.sender_ip != client_ip:
        app.logger.error(f"Unauthorized status check from {client_ip} for session {session_token}")
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify({
        'status': upload_session.status,
        'updated_at': upload_session.created_at.isoformat()
    })

@app.route('/mark_file_failed/<int:file_id>', methods=['POST'])
def mark_file_failed(file_id):
    """Mark a file as failed"""
    client_ip = get_client_ip()
    
    file = UploadSession.query.filter_by(id=file_id).first()
    if not file:
        return jsonify({"error": "File not found"}), 404
    
    if file.receiver_ip != client_ip:
        return jsonify({"error": "You are not authorized to mark this file as failed"}), 403
    
    file.update_status('failed')
    db.session.commit()
    
    from event_manager import emit_status_change
    emit_status_change(file)
    
    return jsonify({
        "message": "File marked as failed successfully",
        "status": "failed"
    })

@app.route('/receiver_host/approval')
def receiver_host_approval():
    """Page for managing host join requests"""
    client_ip = get_client_ip()
    
    # Get pending requests
    pending_requests = HostJoinRequest.query.filter_by(
        host_owner_ip=client_ip,
        status='pending'
    ).order_by(HostJoinRequest.created_at.desc()).all()
    
    # Get approved hosts
    approved_hosts = HostJoinRequest.query.filter_by(
        host_owner_ip=client_ip,
        status='approved'
    ).order_by(HostJoinRequest.approved_at.desc()).all()
    
    now = datetime.now()
    
    return render_template('host_approval.html',
                         pending_requests=pending_requests,
                         approved_hosts=approved_hosts,
                         now=now)

@app.route('/host/<int:host_id>/request_join', methods=['POST'])
def request_join_host(host_id):
    """Send a request to join a host"""
    if not request.form.get('csrf_token'):
        return jsonify({'error': 'CSRF token missing'}), 400
    print(1)
    client_ip = get_client_ip()
    host = Host.query.get_or_404(host_id)
    print(2)
    existing_request = HostJoinRequest.query.filter_by(
        host_id=host_id,
        sender_ip=client_ip
    ).first()
    print(3)
    if existing_request:
        if existing_request.status == 'pending':
            flash('You already have a pending request for this host.', 'warning')
            print(4)
            return redirect(url_for('sender_select_host'))

        elif existing_request.status in ['rejected', 'revoked']:
            existing_request.status = 'pending'
            existing_request.created_at = datetime.utcnow()
            existing_request.message = f"Hello! {client_ip}"
            existing_request.approved_at = None
            existing_request.rejected_at = None
            existing_request.revoked_at = None
            existing_request.response_message = None
            print(5)
            db.session.commit()
            print(6)
            flash('Your previous request was reset to pending.', 'info')
            notify_new_join_request(existing_request)
            print(7)
            return redirect(url_for('sender_select_host'))
            
    else:
        join_request = HostJoinRequest(
            host_id=host_id,
            sender_ip=client_ip,
            host_owner_ip=host.created_by,
            message=f"Hello! {client_ip}",
            status='pending',
            created_at=datetime.utcnow()
        )
        print(8)
        db.session.add(join_request)
        print(9)
        db.session.commit()
        print(10)
    
    notify_new_join_request(join_request)
    print(11)
    flash('Join request sent successfully.', 'success')
    return redirect(url_for('sender_select_host'))

@app.route('/host/request/<int:request_id>/approve', methods=['POST'])
def approve_join_request(request_id):
    """Approve a host join request"""
    if not request.form.get('csrf_token'):
        return jsonify({'error': 'CSRF token missing'}), 400
        
    client_ip = get_client_ip()
    join_request = HostJoinRequest.query.get_or_404(request_id)
    
    if join_request.host_owner_ip != client_ip:
        return jsonify({'error': 'Unauthorized'}), 403
    
    join_request.status = 'approved'
    join_request.approved_at = datetime.utcnow()
    join_request.response_message = "Really!"
    db.session.commit()
    
    notify_request_approved(join_request)
    
    return redirect(url_for('receiver_host_approval'))

@app.route('/host/request/<int:request_id>/reject', methods=['POST'])
def reject_join_request(request_id):
    """Reject a host join request"""
    if not request.form.get('csrf_token'):
        return jsonify({'error': 'CSRF token missing'}), 400
        
    client_ip = get_client_ip()
    join_request = HostJoinRequest.query.get_or_404(request_id)
    
    # Verify ownership
    if join_request.host_owner_ip != client_ip:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Update request status
    join_request.status = 'rejected'
    join_request.rejected_at = datetime.utcnow()
    db.session.commit()
    
    # Notify the sender
    notify_request_rejected(join_request)
    
    return redirect(url_for('receiver_host_approval'))

@app.route('/host/<int:host_id>/revoke', methods=['POST'])
def revoke_host_access(host_id):
    """Revoke access for an approved host"""
    if not request.form.get('csrf_token'):
        return jsonify({'error': 'CSRF token missing'}), 400
        
    client_ip = get_client_ip()
    host = Host.query.get_or_404(host_id)
    
    # Verify ownership
    if host.created_by != client_ip:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Find and update all approved requests for this host
    approved_requests = HostJoinRequest.query.filter_by(
        host_id=host_id,
        status='approved'
    ).all()
    
    for req in approved_requests:
        req.status = 'revoked'
        req.revoked_at = datetime.utcnow()
        notify_access_revoked(req)
    
    db.session.commit()
    
    flash('Access revoked successfully.', 'success')
    return redirect(url_for('receiver_host_approval'))

@app.route('/sender/keys')
def sender_key_management():
    """Key management page for senders"""
    client_ip = get_client_ip()
    ip_mapping = IPKeyMapping.query.filter_by(ip_address=client_ip).first()
    
    has_keys = ip_mapping is not None
    public_key = ip_mapping.public_key_pem if ip_mapping else None
    private_key = ip_mapping.private_key_pem if ip_mapping else None
    
    return render_template('key_management.html',
                         has_keys=has_keys,
                         public_key=public_key,
                         private_key=private_key)

@app.errorhandler(404)
def not_found(error):
    return render_template('index.html', step='error', error_message='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('index.html', step='error', error_message='Internal server error'), 500

@app.route('/file_metadata/<session_token>')
def get_file_metadata(session_token):
    """Get file metadata for verification"""
    try:
        upload_session = UploadSession.query.filter_by(session_token=session_token).first()
        if not upload_session:
            return jsonify({'error': 'File not found'}), 404

        client_ip = get_client_ip()
        if upload_session.receiver_ip != client_ip:
            return jsonify({'error': 'Unauthorized'}), 403

        metadata = upload_session.get_metadata()
        decoded_metadata = {
            'filename': upload_session.filename,
            'timestamp': metadata['metadata']['timestamp'],
            'sender_ip': metadata['metadata']['sender_ip'],
            'iv': metadata['iv'],
            'file_hash': upload_session.file_hash,
            'signature': metadata['metadata_signature'],
            'sender_key': IPKeyMapping.query.filter_by(
                ip_address=upload_session.sender_ip
            ).first().public_key_pem
        }

        return jsonify(decoded_metadata)

    except Exception as e:
        app.logger.error(f"Error getting file metadata: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
