import os
import time
from dotenv import load_dotenv
load_dotenv()
from backend.app import create_app
from backend.extensions import db
import backend.models

app = create_app('testing')
with app.app_context():
    print("Creating all tables...")
    for i in range(3):
        try:
            db.create_all()
            print("All tables recreated.")
            break
        except Exception as e:
            print(f"Attempt {i+1} failed: {e}")
            time.sleep(2)
