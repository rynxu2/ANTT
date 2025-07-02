import os
import json
import hashlib
import secrets
import base64
from datetime import datetime
from flask import request, render_template, jsonify, session, flash, redirect, url_for, send_file
from app import app, db
from models import IPUserKeyMapping, IPHostKeyMapping, UploadSession, Host, HostJoinRequest
from drive_utils import drive_manager, SCOPES
from google_auth_oauthlib.flow import InstalledAppFlow

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
    cleanup_temp_files
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

@app.route('/')
def index():
    """Landing page to choose between Receiver and Sender mode"""
    return render_template('index.html')

@app.route('/get_ip')
def get_ip():
    """Get the client's IP address"""
    client_ip = get_client_ip()
    if not client_ip:
        return jsonify({'error': 'Invalid IP address'}), 400
    return jsonify({'ip_address': client_ip})

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
    
@app.route('/api/register_key/<string:type>', methods=['POST'])
def register_key(type):
    if type not in ['sender', 'receiver']:
        return jsonify({'error': 'Invalid type specified'}), 400
    
    data = request.get_json() or {}
    print(f"Received data for {type} key registration: {data}")
    
    client_ip = get_client_ip()
    if type == 'sender':
        existing_mapping = IPUserKeyMapping.query.filter_by(ip_address=client_ip).first()
        if existing_mapping:
            if existing_mapping.has_keys != True:
                existing_mapping.has_keys = True
                existing_mapping.public_key = data.get('public_key')
                db.session.commit()
                
            return jsonify({
                'message': 'Sender key already registered',
                'ip_address': client_ip,
                'created_at': existing_mapping.created_at.isoformat()
            }), 200
        ip_mapping = IPUserKeyMapping(
            ip_address=client_ip,
            has_keys=True,
            public_key=data.get('public_key'),
            created_at=datetime.utcnow(),
        )
    else:
        existing_mapping = IPHostKeyMapping.query.filter_by(
            host_ip=client_ip,
            host_name=data.get('host_name', 'default')
        ).first()
        if existing_mapping:
            if existing_mapping.has_keys != True:
                existing_mapping.has_keys = True
                existing_mapping.public_key = data.get('public_key')
                db.session.commit()
                
            return jsonify({
                'message': 'Receiver key already registered',
                'ip_address': client_ip,
                'created_at': existing_mapping.created_at.isoformat()
            }), 200
        ip_mapping = IPHostKeyMapping(
            host_ip=client_ip,
            host_name=data.get('host_name', 'default'),
            has_keys=True,
            public_key=data.get('public_key'),
            created_at=datetime.utcnow(),
        )
    db.session.add(ip_mapping)
    db.session.commit()
    return jsonify({
        'message': f'{type.capitalize()} key registered successfully',
        'ip_address': client_ip,
        'created_at': ip_mapping.created_at.isoformat()
    })

@app.route('/receiver_hosts')
def receiver_hosts():
    """List all hosts"""
    client_ip = get_client_ip()
    hosts = Host.query.filter_by(ip_address=client_ip).all()
    return render_template('hosts.html', hosts=hosts, client_ip=client_ip)

@app.route('/hosts/add', methods=['POST'])
def add_host():
    """Add a new host"""
    host_ip = get_client_ip()
    name = request.form.get('name')
    description = request.form.get('description')
    has_keys = request.form.get('has_keys').lower() == 'true'
    public_key = request.form.get('public_key')
    
    if not name:
        flash('Host name is required', 'error')
        return redirect(url_for('receiver_hosts'))
    
    existing_host = Host.query.filter_by(created_by=host_ip, name=name).first()
    if existing_host:
        flash('A host with this name already exists for your IP', 'error')
        return redirect(url_for('receiver_hosts'))
    
    ip_mapping = IPHostKeyMapping.query.filter_by(host_ip=host_ip, host_name=name).first()
    if not ip_mapping:
        try:
            ip_mapping = IPHostKeyMapping(
                host_ip=host_ip,
                host_name=name,
                has_keys=has_keys,
                public_key=public_key if has_keys else None,    
            )
            
            db.session.add(ip_mapping)
            db.session.commit()
            flash('RSA keys generated successfully', 'success')
        except Exception as e:
            flash(f'Error generating RSA keys: {str(e)}', 'error')
            return redirect(url_for('receiver_hosts'))
    
    new_host = Host(
        name=name,
        ip_address=host_ip,
        description=description,
        created_by=host_ip,
        has_keys=has_keys,
        public_key=public_key if has_keys else None
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
        join_requests = HostJoinRequest.query.filter_by(host_id=host_id).all()
        for request in join_requests:
            db.session.delete(request)
        
        upload_sessions = UploadSession.query.filter_by(
            receiver_ip=host.ip_address,
            receiver_name=host.name
        ).all()
        
        for session in upload_sessions:
            if os.path.exists(session.filepath):
                try:
                    os.remove(session.filepath)
                except Exception as e:
                    app.logger.error(f"Failed to delete file for session {session.session_token}: {str(e)}")
            db.session.delete(session)
        
        db.session.delete(host)
        db.session.commit()
        notify_host_deleted(host_id)
        flash('Host, associated join requests and upload sessions deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting host: {str(e)}', 'error')
    
    return redirect(url_for('receiver_hosts'))

@app.route('/sender_select_host')
def sender_select_host():
    """Display available hosts for selection"""
    
    client_ip = get_client_ip()
    ip_mapping = IPUserKeyMapping.query.filter_by(ip_address=client_ip).first()
    
    if not ip_mapping:
        try:
            ip_mapping = IPUserKeyMapping(
                ip_address=client_ip
            )
            db.session.add(ip_mapping)
            db.session.commit()
        except Exception as e:
            flash(f'Error generating RSA keys: {str(e)}', 'error')
            return redirect(url_for('sender_dashboard'))
        
    hosts = Host.query.all()
    
    host_requests = {}
    join_requests = HostJoinRequest.query.filter_by(
        sender_ip=client_ip
    ).order_by(HostJoinRequest.created_at.desc()).all()
    
    for request in join_requests:
        if request.host_id not in host_requests:
            host_requests[request.host_id] = {}
            
        if request.host_name not in host_requests[request.host_id]:
            host_requests[request.host_id][request.host_name] = {
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
    
    if not host.has_keys:
        flash('Selected host does not have a public key available', 'error')
        return redirect(url_for('sender_select_host'))
    
    session['selected_host_id'] = host_id
    session['selected_host_name'] = host.name
    session['selected_host_ip'] = host.ip_address
    session['selected_host_has_keys'] = host.has_keys
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
            receiver_ip=selected_host.ip_address,
            receiver_name=selected_host.name
        ).order_by(UploadSession.created_at.desc()).all()
    else:
        host_ips = [host.ip_address for host in hosts]
        received_files = UploadSession.query.filter(
            UploadSession.receiver_ip.in_(host_ips)
        ).order_by(UploadSession.created_at.desc()).all()
    
    stats = {
        'total_files': len(received_files),
        'total_size': sum(f.file_size for f in received_files if f.file_size),
        'completed_files': len([f for f in received_files if f.status in [FILE_STATUS['VERIFIED'], FILE_STATUS['DOWNLOADED']]]),
    }
    
    return render_template('received_files.html',
                         hosts=hosts,
                         selected_host_id=selected_host_id,
                         received_files=received_files,
                         stats=stats)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle secure file upload (client-side encryption)"""
    app.logger.info("Starting file upload process (client-side encryption)")

    csrf_token = request.headers.get('X-CSRFToken')
    if not csrf_token:
        app.logger.error("CSRF token missing in headers")
        return jsonify({'error': 'CSRF token missing'}), 400

    if 'file' not in request.files:
        app.logger.error("No file found in request.files")
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    iv_b64 = request.form.get('iv')
    file_hash = request.form.get('hash')
    encrypted_session_key_b64 = request.form.get('encrypted_session_key')
    metadata_json = request.form.get('metadata')
    metadata_signature_b64 = request.form.get('sig')
    file_drive_id = request.form.get('file_drive_id')
    file_drive_link = request.form.get('file_drive_link')
    file_source_type = request.form.get('file_source_type')

    if file.filename == '':
        app.logger.error("Uploaded file has empty filename")
        return jsonify({'error': 'No selected file'}), 400

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
            receiver_name=host.name,
            status=FILE_STATUS['PENDING']
        ).order_by(UploadSession.created_at.desc()).first()
    except Exception as e:
        app.logger.error(f"Database error while querying UploadSession: {str(e)}")
        return jsonify({'error': 'Server error querying uploads'}), 500

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
        temp_path, _ = store_temp_file(file)
        app.logger.info(f"Temporary encrypted file stored at: {temp_path}")

        session_token = secrets.token_urlsafe(48)

        encrypted_path = move_temp_to_permanent(temp_path, session_token, file.filename)
        app.logger.info(f"Encrypted file moved to: {encrypted_path}")

        upload_session = UploadSession(
            sender_ip=sender_ip,
            receiver_ip=host.ip_address,
            receiver_name=host.name,
            session_token=session_token,
            filename=file.filename,
            file_hash=file_hash,
            file_size=os.path.getsize(encrypted_path),
            filepath=encrypted_path,
            drive_file_id=file_drive_id,
            drive_link=file_drive_link,
            source_type=file_source_type,
            status=FILE_STATUS['PENDING']
        )

        metadata = {
            'iv': iv_b64,
            'encrypted_session_key': encrypted_session_key_b64,
            'metadata': json.loads(metadata_json) if metadata_json else {},
            'metadata_signature': metadata_signature_b64
        }
        upload_session.set_metadata(metadata)

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
            'file_hash': file_hash,
            'metadata': metadata
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
    """Download file: if verified/downloaded, return decrypted; else, return encrypted file as-is"""
    try:
        upload_session = UploadSession.query.filter_by(session_token=session_token).first()
        if not upload_session:
            return jsonify({'error': 'Invalid session token'}), 404
        
        if upload_session.status in [FILE_STATUS['VERIFIED'], FILE_STATUS['DOWNLOADED']]:
            client_ip = get_client_ip()
            key_mapping = IPHostKeyMapping.query.filter_by(
                host_ip=client_ip, 
                host_name=upload_session.receiver_name
            ).first()
            if not key_mapping:
                return jsonify({'error': 'Recipient keys not found'}), 404
            
            metadata = upload_session.get_metadata()
            iv = base64.b64decode(metadata['iv'])
            encrypted_session_key = base64.b64decode(metadata['encrypted_session_key'])
            session_key = decrypt_with_private_key(
                encrypted_session_key,
                key_mapping.private_key_pem
            )
            
            with open(upload_session.filepath, 'rb') as f:
                file_contents = f.read()
            stored_iv = file_contents[:16]
            encrypted_data = file_contents[16:]
            
            if stored_iv != iv:
                app.logger.error("IV mismatch between stored file and metadata")
                return jsonify({'error': 'IV verification failed'}), 400
            if not verify_file_hash(stored_iv, encrypted_data, upload_session.file_hash):
                app.logger.error("File integrity check failed during download")
                return jsonify({'error': 'File integrity check failed'}), 400
            
            decrypted_data = decrypt_file_aes(encrypted_data, session_key, stored_iv)
            try:
                file_stream = io.BytesIO(decrypted_data)
                print(f"Before status update: {upload_session.status}")
                upload_session.update_status(FILE_STATUS['DOWNLOADED'])
                upload_session.downloaded_at = datetime.utcnow()
                db.session.commit()
                print(f"After status update: {upload_session.status}")
                notify_status_change(upload_session)
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
                        print(f"Before status update: {upload_session.status}")
                        upload_session.status = FILE_STATUS['VERIFIED']
                        upload_session.downloaded_at = None
                        db.session.commit()
                        print(f"After status update: {upload_session.status}")
                        notify_status_change(upload_session)
                return response
            except Exception as e:
                db.session.rollback()
                print(f"Before status update: {upload_session.status}")
                upload_session.status = FILE_STATUS['VERIFIED']
                upload_session.downloaded_at = None
                db.session.commit()
                print(f"After status update: {upload_session.status}")
                notify_status_change(upload_session)
                raise
        else:
            return send_file(
                upload_session.filepath,
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=upload_session.filename + '.enc'
            )
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
    if not IPUserKeyMapping.query.filter_by(ip_address=client_ip).first():
        return redirect(url_for('sender_dashboard'))
    
    return render_template('secure_upload.html', selected_host=selected_host)

@app.route('/transfer_status/<session_token>')
def transfer_status(session_token):
    """Get status of a file transfer session"""
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

    client_ip = get_client_ip()
    host = Host.query.get_or_404(host_id)

    existing_request = HostJoinRequest.query.filter_by(
        host_id=host_id,
        host_name=host.name,
        sender_ip=client_ip
    ).first()

    if existing_request:
        if existing_request.status == 'pending':
            flash('You already have a pending request for this host.', 'warning')
            return redirect(url_for('sender_select_host'))

        elif existing_request.status in ['rejected', 'revoked']:
            existing_request.status = 'pending'
            existing_request.created_at = datetime.utcnow()
            existing_request.approved_at = None
            existing_request.rejected_at = None
            existing_request.revoked_at = None
            existing_request.response_message = None
            db.session.commit()
            
            flash('Your previous request was reset to pending.', 'info')
            notify_new_join_request(existing_request)

            return redirect(url_for('sender_select_host'))
            
    else:
        join_request = HostJoinRequest(
            host_id=host_id,
            host_name=host.name,
            sender_ip=client_ip,
            host_owner_ip=host.created_by,
            message=f"Hello! {client_ip}",
            status='pending',
            created_at=datetime.utcnow()
        )
        db.session.add(join_request)
        db.session.commit()
    
    notify_new_join_request(join_request)

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
    ip_mapping = IPUserKeyMapping.query.filter_by(ip_address=client_ip).first()
    
    if not ip_mapping:
        has_keys = False
    else:
        has_keys = True
    
    return render_template('key_management.html',
                         has_keys=has_keys)

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
            'host_name': upload_session.receiver_name,
            'encrypted_session_key': metadata['encrypted_session_key'],
            'iv': metadata['iv'],
            'file_hash': upload_session.file_hash,
            'signature': metadata['metadata_signature'],
            'sender_key': IPUserKeyMapping.query.filter_by(
                ip_address=upload_session.sender_ip
            ).first().public_key,
            'status': upload_session.status,
            'fail_step':  upload_session.fail_step if hasattr(upload_session, 'fail_step') else None,
            'error_message': upload_session.error_message if hasattr(upload_session, 'error_message') else None
        }

        return jsonify(decoded_metadata)

    except Exception as e:
        app.logger.error(f"Error getting file metadata: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/oauth2callback')
def oauth2callback():
    """Handle Google OAuth2 callback"""
    host_id = request.args.get('host_id') or session.get('authenticating_host_id')
    if not host_id:
        return render_template('oauth2callback.html', success=False, error='Missing host_id')
    session['authenticating_host_id'] = host_id
    
    if request.args.get('code'):
        try:
            flow = InstalledAppFlow.from_client_secrets_file(
                'client_secret_326222266772-n102mfh5tjuq7305d5m0jlr7fcn9if4q.apps.googleusercontent.com.json',
                SCOPES
            )
            
            flow.fetch_token(
                authorization_response=request.url,
                code=request.args.get('code')
            )
            
            credentials = flow.credentials
            drive_manager.save_credentials(credentials, host_id)
            session.pop('authenticating_host_id', None)
            
            return render_template('oauth2callback.html', success=True)
            
        except Exception as e:
            app.logger.error(f"OAuth callback error: {str(e)}")
            return render_template('oauth2callback.html', success=False, error=str(e))
    
    try:
        flow = InstalledAppFlow.from_client_secrets_file(
            'client_secret_326222266772-n102mfh5tjuq7305d5m0jlr7fcn9if4q.apps.googleusercontent.com.json',
            SCOPES,
            redirect_uri=request.base_url
        )
        
        auth_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true', 
            redirect_uri=request.base_url
        )
        
        return redirect(auth_url)
        
    except Exception as e:
        app.logger.error(f"OAuth error: {str(e)}")
        return render_template('oauth2callback.html', success=False, error=str(e))

@app.route('/verify/<session_token>/<status>', methods=['POST'])
def complete_verification(session_token, status):
    upload_session = UploadSession.query.filter_by(session_token=session_token).first()
    if not upload_session:
        app.logger.error(f"Verification failed: Invalid session token {session_token}")
        return jsonify({'error': 'Invalid session token'}), 400
    try:
        if status == 'verified':
            upload_session.update_status(FILE_STATUS['VERIFIED'])
        elif status == 'failed':
            upload_session.update_status(FILE_STATUS['FAILED'])
        elif status == 'downloaded':
            upload_session.update_status(FILE_STATUS['DOWNLOADED'])
        else:
            app.logger.error(f"Verification failed: Invalid status '{status}' for session {session_token}")
            return jsonify({'error': 'Invalid status'}), 400

        db.session.commit()
        notify_status_change(upload_session)
        return jsonify({'message': 'File verified and completed'})
    except Exception as e:
        app.logger.error(f"Database error during verification for session {session_token}: {str(e)}")
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/raw_encrypted_file/<session_token>')
def api_raw_encrypted_file(session_token):
    """Serve the raw encrypted file for client-side decryption"""
    try:
        upload_session = UploadSession.query.filter_by(session_token=session_token).first()
        if not upload_session:
            return jsonify({'error': 'Invalid session token'}), 404
        if not upload_session.filepath or not os.path.exists(upload_session.filepath):
            return jsonify({'error': 'File not found'}), 404
        # Always serve the encrypted file as-is
        return send_file(
            upload_session.filepath,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=upload_session.filename + '.enc'
        )
    except Exception as e:
        app.logger.error(f"/api/raw_encrypted_file error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500