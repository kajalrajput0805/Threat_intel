# create_user.py
from app import create_app, db
from app.models import User
from werkzeug.security import generate_password_hash

app = create_app()
with app.app_context():
    username = input("Enter new admin username: ")
    raw_password = input("Enter password:  ")
    hashed_password = generate_password_hash(raw_password)

    # Check if user already exists
    existing = User.query.filter_by(username=username).first()
    if existing:
        print(" User already exists.")
    else:
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        print(f"Admin user '{username}' created successfully.")
