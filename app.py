from flask import Flask, request, jsonify, send_from_directory, redirect, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.email}>'

# Create database tables
with app.app_context():
    db.create_all()

# Serve static files
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect('/login.html')
    return send_from_directory('.', 'home.html')

@app.route('/<path:path>')
def send_file(path):
    return send_from_directory('.', path)

# API endpoints
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing email or password'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400

    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        email=data['email'],
        password=hashed_password,
        name=data.get('name', '')
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing email or password'}), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Invalid email or password'}), 401

    session['user_id'] = user.id
    return jsonify({
        'message': 'Login successful',
        'user': {
            'email': user.email,
            'name': user.name
        }
    }), 200

@app.route('/api/google-login', methods=['POST'])
def google_login():
    data = request.get_json()
    
    if not data or not data.get('email'):
        return jsonify({'error': 'Missing email'}), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user:
        # Create new user for Google Sign-In
        new_user = User(
            email=data['email'],
            password=generate_password_hash('google-oauth'),  # Placeholder password
            name=data.get('name', '')
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            user = new_user
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': 'Login failed'}), 500

    session['user_id'] = user.id
    return jsonify({
        'message': 'Login successful',
        'user': {
            'email': user.email,
            'name': user.name
        }
    }), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200

if __name__ == '__main__':
    app.run(port=8000, debug=True) 