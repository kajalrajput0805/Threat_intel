from app import create_app, db
from app.models import ClientUser
from werkzeug.security import generate_password_hash

app = create_app()
with app.app_context():
    username = input("Enter username: ")
    password = input("Enter password: ")
    hashed_password = generate_password_hash(password)

    if ClientUser.query.filter_by(username=username).first():
        print("⚠️ User already exists.")
    else:
        user = ClientUser(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        print("✅ Client user created.")

 