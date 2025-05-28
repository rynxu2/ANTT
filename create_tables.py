from app import app, db
from models import Host

with app.app_context():
    db.create_all()
