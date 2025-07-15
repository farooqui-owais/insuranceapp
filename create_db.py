# In your Python interpreter (or create a create_db.py file)
from app import app, db
with app.app_context():
    db.create_all()
    print("Database created!")