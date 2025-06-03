from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return "None"

# Create tables
with app.app_context():
    db.drop_all()  # Drop all existing tables
    db.create_all()  # Create new tables with updated schema
    
    # Create a test user
    test_user = User(
        email='test@example.com',
        password=generate_password_hash('Test@123'),
        first_name='John',
        last_name='Doe'
    )
    
    db.session.add(test_user)
    db.session.commit()
    print("Test user created successfully!") 