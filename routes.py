import os
import json
import hashlib
import secrets
import base64
from datetime import datetime
from flask import request, render_template, jsonify, session, flash, redirect, url_for, send_file
from werkzeug.utils import secure_filename
from app import app, db
from models import IPKeyMapping, UploadSession, Host
from crypto_utils import (
    generate_rsa_keypair, 
    encrypt_with_public_key, 
    decrypt_with_private_key,
    sign_data,
    verify_signature,
    encrypt_file_aes,
    decrypt_file_aes,
    generate_session_key
)
from storage_utils import (
    store_temp_file,
    move_temp_to_permanent,
    cleanup_temp_files,
    UPLOAD_FOLDER
)
import io

def get_client_ip():
    """Get the real client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def ensure_sender_keys():
    """Ensure the current IP has RSA keys, create if not exists"""
    client_ip = get_client_ip()
    ip_mapping = IPKeyMapping.query.filter_by(ip_address=client_ip).first()
    
    if not ip_mapping:
        try:
            # Generate new RSA key pair
            public_key_pem, private_key_pem = generate_rsa_keypair()
            
            # Save to database
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
    
    # Get all hosts owned by this IP
    hosts = Host.query.filter_by(created_by=client_ip).all()
    
    # Get all files received by these hosts
    host_ips = [host.ip_address for host in hosts]
    received_files = UploadSession.query.filter(
        UploadSession.receiver_ip.in_(host_ips)
    ).all()
    
    # Calculate statistics
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
    
    # Ensure sender has RSA keys
    if not ensure_sender_keys():
        flash('Error generating RSA keys. Please try again.', 'error')
    
    # Get all transfers by this sender
    all_transfers = UploadSession.query.filter_by(sender_ip=client_ip).all()
    
    # Get recent transfers
    recent_transfers = UploadSession.query.filter_by(
        sender_ip=client_ip
    ).order_by(
        UploadSession.created_at.desc()
    ).limit(5).all()
    
    # Calculate statistics
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
        # Check if keys already exist
        existing_mapping = IPKeyMapping.query.filter_by(ip_address=client_ip).first()
        if existing_mapping:
            return jsonify({
                'success': True,
                'message': 'Keys already exist for this IP',
                'public_key': existing_mapping.public_key_pem
            })
        
        # Generate new RSA key pair
        public_key_pem, private_key_pem = generate_rsa_keypair()
        
        # Save to database
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

from events import notify_new_host, notify_status_change, notify_new_file, notify_host_deleted

@app.route('/hosts/add', methods=['POST'])
def add_host():
    """Add a new host"""
    client_ip = get_client_ip()
    name = request.form.get('name')
    description = request.form.get('description')
    
    # Check if host with same name exists for this IP
    existing_host = Host.query.filter_by(created_by=client_ip, name=name).first()
    if existing_host:
        flash('A host with this name already exists for your IP', 'error')
        return redirect(url_for('receiver_hosts'))
    
    # Check and create RSA keys if needed
    ip_mapping = IPKeyMapping.query.filter_by(ip_address=client_ip).first()
    if not ip_mapping:
        try:
            # Generate new RSA key pair
            public_key_pem, private_key_pem = generate_rsa_keypair()
            
            # Save to database
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
    
    # Create new host with the public key
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
        # Notify all clients about the new host
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
    
    # Only allow deletion if the host was created by the current IP
    if host.created_by != client_ip:
        flash('You can only delete hosts that you created', 'error')
        return redirect(url_for('receiver_hosts'))
    
    try:
        db.session.delete(host)
        db.session.commit()
        # Notify all clients about the host deletion
        notify_host_deleted(host_id)
        flash('Host deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting host: {str(e)}', 'error')
    
    return redirect(url_for('receiver_hosts'))

@app.route('/sender_select_host')
def sender_select_host():
    """Display available hosts for selection"""
    client_ip = get_client_ip()
    
    # Ensure sender has RSA keys
    if not ensure_sender_keys():
        flash('Error generating RSA keys. Please try again.', 'error')
        return redirect(url_for('sender_dashboard'))
    
    # Get all available hosts
    hosts = Host.query.all()
    return render_template('select_host.html', hosts=hosts)

@app.route('/select_host/<int:host_id>', methods=['POST'])
def select_upload_host(host_id):
    """Select a host for file upload"""
    client_ip = get_client_ip()
    host = Host.query.get_or_404(host_id)
    
    # Check if host has public key
    if not host.public_key:
        flash('Selected host does not have a public key available', 'error')
        return redirect(url_for('sender_select_host'))
    
    # Store selected host and its info in session
    session['selected_host_id'] = host_id
    session['selected_host_name'] = host.name
    session['selected_host_ip'] = host.ip_address
    session['selected_host_public_key'] = host.public_key
    session['mode'] = 'sender'  # Set the mode explicitly
    
    app.logger.info(f"Host selected - ID: {host_id}, Name: {host.name}, IP: {host.ip_address}")
    
    # Proceed to secure upload page
    return redirect(url_for('sender_secure_upload'))

@app.route('/receiver_files')
def receiver_files():
    """Display files received by the user's hosts"""
    client_ip = get_client_ip()
    
    # Get all hosts owned by this IP
    hosts = Host.query.filter_by(created_by=client_ip).all()
    
    # Get selected host from query parameter
    selected_host_id = request.args.get('host_id', type=int)
    if selected_host_id:
        selected_host = Host.query.get_or_404(selected_host_id)
        # Verify ownership
        if selected_host.created_by != client_ip:
            flash('Access denied', 'error')
            return redirect(url_for('receiver_files'))
        
        # Get files for selected host
        received_files = UploadSession.query.filter_by(
            receiver_ip=selected_host.ip_address
        ).order_by(UploadSession.created_at.desc()).all()
    else:
        # Get files for all hosts owned by this IP
        host_ips = [host.ip_address for host in hosts]
        received_files = UploadSession.query.filter(
            UploadSession.receiver_ip.in_(host_ips)
        ).order_by(UploadSession.created_at.desc()).all()
    
    # Calculate statistics
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
    
    # Check CSRF token (debug logging)
    csrf_token = request.headers.get('X-CSRFToken')
    if not csrf_token:
        app.logger.error("No CSRF token in headers")
        return jsonify({'error': 'CSRF token missing'}), 400
    
    if 'file' not in request.files:
        app.logger.error("No file in request")
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        app.logger.error("Empty filename")
        return jsonify({'error': 'No selected file'}), 400

    app.logger.info(f"Processing file: {file.filename}")

    # Get selected host and validate
    selected_host_id = session.get('selected_host_id')
    if not selected_host_id:
        app.logger.error("No host selected in session")
        return jsonify({'error': 'No host selected'}), 400
    
    # Check if sender already has an active file for this host
    host = Host.query.get(selected_host_id)
    if not host:
        app.logger.error(f"Invalid host ID: {selected_host_id}")
        return jsonify({'error': 'Invalid host'}), 400

    sender_ip = get_client_ip()
    existing_file = UploadSession.query.filter_by(
        sender_ip=sender_ip,
        receiver_ip=host.ip_address
    ).first()

    # Only allow new upload if there's no existing file or if existing file is verified/failed
    if existing_file and existing_file.status not in ['verified', 'failed']:
        app.logger.error(f"Sender {sender_ip} already has a pending file for host {host.ip_address}")
        return jsonify({
            'error': 'You already have a pending file for this host. Please wait for verification or mark it as failed before uploading a new file.'
        }), 400

    # Continue with file upload if validation passes...
    temp_path = None
    encrypted_path = None
    try:
        # Store file temporarily
        temp_path, file_hash = store_temp_file(file)
        app.logger.info(f"File stored temporarily at: {temp_path}")
        
        # Generate session key and token
        session_token = secrets.token_urlsafe(48)
        session_key = generate_session_key()
        
        # Encrypt file
        with open(temp_path, 'rb') as f:
            file_data = f.read()
            
        try:
            # Encrypt session key with host's public key
            encrypted_session_key = encrypt_with_public_key(session_key, host.public_key)
        except Exception as e:
            app.logger.error(f"Session key encryption failed: {str(e)}")
            raise Exception("File encryption failed: Unable to encrypt session key")
        
        # Encrypt file data
        encrypted_data, iv = encrypt_file_aes(file_data, session_key)
        app.logger.info(f"File encrypted: {len(encrypted_data)} bytes")
        
        # Move to permanent storage
        encrypted_path = move_temp_to_permanent(temp_path, session_token, file.filename)
        
        # Write encrypted data
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        app.logger.info(f"Encrypted file saved at: {encrypted_path}")            # Create session record
        upload_session = UploadSession(
            sender_ip=get_client_ip(),
            receiver_ip=host.ip_address,
            session_token=session_token,
            filename=file.filename,
            file_hash=file_hash,
            file_size=len(file_data),
            filepath=encrypted_path,
            status='pending'
        )
        
        # Store encryption metadata
        metadata = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8')
        }
        upload_session.set_metadata(metadata)
        
        db.session.add(upload_session)
        db.session.commit()
        
        # Notify about new file upload
        app.logger.info("Emitting new_file event")
        try:
            notify_new_file(upload_session)
            app.logger.info(f"New file event emitted for session: {upload_session.session_token}")
        except Exception as notify_error:
            app.logger.error(f"Error sending new file notification: {str(notify_error)}")
        app.logger.info("Upload session created and saved")
        
        return jsonify({
            'message': 'File uploaded successfully',
            'session_token': session_token,
            'file_hash': file_hash
        })
        
    except Exception as e:
        app.logger.error(f"Upload error: {str(e)}")
        # Clean up any temporary files
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                app.logger.info(f"Cleaned up temp file: {temp_path}")
            except Exception as cleanup_error:
                app.logger.error(f"Error cleaning temp file: {cleanup_error}")
        
        if encrypted_path and os.path.exists(encrypted_path):
            try:
                os.remove(encrypted_path)
                app.logger.info(f"Cleaned up encrypted file: {encrypted_path}")
            except Exception as cleanup_error:
                app.logger.error(f"Error cleaning encrypted file: {cleanup_error}")
                
        if 'upload_session' in locals():
            try:
                db.session.rollback()
                app.logger.info("Database session rolled back")
            except Exception as db_error:
                app.logger.error(f"Error rolling back session: {db_error}")
        
        return jsonify({'error': str(e)}), 500
    finally:
        cleanup_temp_files()
        app.logger.info("Cleanup completed")

@app.route('/download/<session_token>')
def download_file(session_token):
    """Handle secure file download"""
    try:
        # Get upload session
        upload_session = UploadSession.query.filter_by(session_token=session_token).first()
        if not upload_session:
            return jsonify({'error': 'Invalid session token'}), 404
        
        # Only verified files can be downloaded
        if upload_session.status != 'verified':
            return jsonify({'error': 'File not verified'}), 400
        
        # Get recipient's key mapping
        client_ip = get_client_ip()
        key_mapping = IPKeyMapping.query.filter_by(ip_address=client_ip).first()
        if not key_mapping:
            return jsonify({'error': 'Recipient keys not found'}), 404
        
        # Get encryption metadata
        metadata = upload_session.get_metadata()
        iv = base64.b64decode(metadata['iv'])
        encrypted_session_key = base64.b64decode(metadata['encrypted_session_key'])
        
        # Decrypt session key
        session_key = decrypt_with_private_key(
            encrypted_session_key,
            key_mapping.private_key_pem
        )
        
        # Decrypt file
        with open(upload_session.filepath, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_file_aes(encrypted_data, session_key, iv)
        
        # Verify file hash
        if hashlib.sha512(decrypted_data).hexdigest() != upload_session.file_hash:
            return jsonify({'error': 'File integrity check failed'}), 400
            
        try:
            # Prepare the file for download
            file_stream = io.BytesIO(decrypted_data)
            
            # Update session status only after successful decryption
            upload_session.update_status('downloaded')
            upload_session.downloaded_at = datetime.utcnow()
            db.session.commit()
            
            # Notify clients about status change
            notify_status_change(upload_session)
            
            app.logger.info(f"File download started: {upload_session.session_token}")
            
            # Notify all clients about the status change
            try:
                notify_status_change(upload_session)
                app.logger.info(f"Download status change notification sent for session: {upload_session.session_token}")
            except Exception as notify_error:
                app.logger.error(f"Error sending download status notification: {str(notify_error)}")
            
            # Send decrypted file
            response = send_file(
                file_stream,
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=upload_session.filename
            )
            
            # Add callback to handle errors during file send
            @response.call_on_close
            def on_close():
                try:
                    file_stream.close()
                except:
                    # If there was an error during send, reset the status
                    upload_session.status = 'verified'
                    upload_session.downloaded_at = None
                    db.session.commit()
                    # Notify about status reset
                    notify_status_change(upload_session)
            
            return response
            
        except Exception as e:
            db.session.rollback()
            upload_session.status = 'verified'
            upload_session.downloaded_at = None
            db.session.commit()
            # Notify about status reset
            notify_status_change(upload_session)
            raise
        
    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/sender_secure_upload')
def sender_secure_upload():
    """Show the secure file upload page"""
    # Check if a host is selected
    selected_host_id = session.get('selected_host_id')
    if not selected_host_id:
        flash('Please select a host first.', 'warning')
        return redirect(url_for('sender_select_host'))
    
    # Get host information
    selected_host = Host.query.get(selected_host_id)
    if not selected_host:
        flash('Selected host not found.', 'error')
        return redirect(url_for('sender_select_host'))
    
    # Check if sender has keys
    client_ip = get_client_ip()
    if not IPKeyMapping.query.filter_by(ip_address=client_ip).first():
        if not ensure_sender_keys():
            flash('Failed to generate sender keys.', 'error')
            return redirect(url_for('sender_dashboard'))
    
    return render_template('secure_upload.html', selected_host=selected_host)

@app.route('/verify_file/<session_token>', methods=['POST'])
def verify_file(session_token):
    """Verify a received file"""
    # Get upload session
    upload_session = UploadSession.query.filter_by(session_token=session_token).first()
    if not upload_session:
        return jsonify({'error': 'Invalid session token'}), 404
    
    # Verify recipient
    client_ip = get_client_ip()
    if upload_session.receiver_ip != client_ip:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # Get recipient's key mapping
        key_mapping = IPKeyMapping.query.filter_by(ip_address=client_ip).first()
        if not key_mapping:
            return jsonify({'error': 'Recipient keys not found'}), 404
        
        # Get encryption metadata
        metadata = upload_session.get_metadata()
        iv = base64.b64decode(metadata['iv'])
        encrypted_session_key = base64.b64decode(metadata['encrypted_session_key'])
        
        # Test decrypt session key with recipient's private key
        try:
            session_key = decrypt_with_private_key(
                encrypted_session_key,
                key_mapping.private_key_pem
            )
        except Exception as e:
            app.logger.error(f"Session key decryption failed: {str(e)}")
            return jsonify({'error': 'Invalid session key'}), 400
        
        # Test decrypt a small portion of the file
        with open(upload_session.filepath, 'rb') as f:
            test_data = f.read(1024)  # Read first 1KB
        
        try:
            decrypted_test = decrypt_file_aes(test_data, session_key, iv)
        except Exception as e:
            app.logger.error(f"Test decryption failed: {str(e)}")
            return jsonify({'error': 'File decryption test failed'}), 400
            
        # If we got here, decryption works - mark as verified
        upload_session.update_status('verified')
        db.session.commit()
        
        app.logger.info(f"File verified successfully: {upload_session.session_token}")
        
        # Notify all clients about the status change
        try:
            notify_status_change(upload_session)
            app.logger.info(f"Status change notification sent for session: {upload_session.session_token}")
        except Exception as notify_error:
            app.logger.error(f"Error sending status change notification: {str(notify_error)}")
        
        return jsonify({
            'message': 'File verified successfully',
            'filename': upload_session.filename,
            'file_size': upload_session.file_size,
            'status': upload_session.status,
            'session_token': upload_session.session_token
        })
        
    except Exception as e:
        app.logger.error(f"Verification error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/transfer_status/<session_token>')
def transfer_status(session_token):
    """Get current status of a file transfer session"""
    app.logger.info(f"Checking status for session: {session_token}")
    
    # Get upload session
    upload_session = UploadSession.query.filter_by(session_token=session_token).first()
    if not upload_session:
        app.logger.error(f"Invalid session token: {session_token}")
        return jsonify({'error': 'Invalid session token'}), 404
    
    # Verify sender
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
    
    # Find the file
    file = UploadSession.query.filter_by(id=file_id).first()
    if not file:
        return jsonify({"error": "File not found"}), 404
    
    # Check if the client is the receiver of this file
    if file.receiver_ip != client_ip:
        return jsonify({"error": "You are not authorized to mark this file as failed"}), 403
    
    # Update the file status to failed
    file.update_status('failed')
    db.session.commit()
    
    # Send realtime notification to both sender and receiver
    from event_manager import emit_status_change
    emit_status_change(file)
    
    return jsonify({
        "message": "File marked as failed successfully",
        "status": "failed"
    })

@app.errorhandler(404)
def not_found(error):
    return render_template('index.html', step='error', error_message='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('index.html', step='error', error_message='Internal server error'), 500
