import os
from app import app, db, socketio

if __name__ == "__main__":
    with app.app_context():
        print("Dropping all tables...")
        db.drop_all()
        print("Creating tables with new schema...")
        db.create_all()
        print("Database schema updated successfully")
        
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
 