import os
import logging
import eventlet
eventlet.monkey_patch()

from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO, join_room, leave_room
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

logging.basicConfig(level=logging.DEBUG)

def get_client_ip():
    """Get the real client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "Av4qf48xSS")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

csrf = CSRFProtect(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///secure_upload.db"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'Av4qf48x'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

db.init_app(app)

socketio = SocketIO(
    app,
    async_mode='eventlet',
    cors_allowed_origins="*",
    logger=True,
    engineio_logger=True,
    ping_timeout=30,
    ping_interval=15
)

@socketio.on('connect')
def handle_connect():
    client_ip = get_client_ip()
    logging.info(f"Client connected from IP: {client_ip}")
    join_room(client_ip)
    socketio.emit('connection_status', {'status': 'connected'}, room=client_ip)

@socketio.on('disconnect')
def handle_disconnect():
    client_ip = get_client_ip()
    logging.info(f"Client disconnected from IP: {client_ip}")
    leave_room(client_ip)

@socketio.on_error()
def error_handler(e):
    client_ip = get_client_ip()
    logging.error(f"SocketIO error for client {client_ip}: {str(e)}")
    socketio.emit('error', {'message': 'An error occurred'}, room=client_ip)

@socketio.on_error_default
def default_error_handler(e):
    client_ip = get_client_ip()
    logging.error(f"Unhandled SocketIO error for client {client_ip}: {str(e)}")
    socketio.emit('error', {'message': 'An unexpected error occurred'}, room=client_ip)