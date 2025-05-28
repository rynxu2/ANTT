import os
from app import app, db
from models import Host, IPKeyMapping, UploadSession

if __name__ == "__main__":
    # Drop all tables and create new ones with updated schema
    with app.app_context():
        print("Dropping all tables...")
        db.drop_all()
        print("Creating tables with new schema...")
        db.create_all()
        print("Database schema updated successfully")
        
    app.run(host="0.0.0.0", port=5000, debug=True)
