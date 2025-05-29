from flask import Flask, request, jsonify, send_from_directory, redirect, session, make_response, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

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
    print("Accessing home route")  # Debug print
    if 'user_id' not in session:
        print("No user_id in session, redirecting to login")  # Debug print
        return redirect('/login')
    print("User is logged in, serving home.html")  # Debug print
    return render_template('home.html')

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect('/')
    return render_template('login.html')

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
    try:
        print("Received login request")  # Debug print
        if not request.is_json:
            print("Request is not JSON")  # Debug print
            return jsonify({'error': 'Missing JSON in request'}), 400

        data = request.get_json()
        print("Received login data:", data)  # Debug print

        # Check for empty email or password
        if not data.get('email') or not data.get('password'):
            print("Missing email or password")  # Debug print
            return jsonify({'error': 'Please enter both email and password'}), 400

        # Check if email and password are empty strings after stripping whitespace
        if not data['email'].strip() or not data['password'].strip():
            print("Empty email or password fields")  # Debug print
            return jsonify({'error': 'Please enter both email and password'}), 400

        user = User.query.filter_by(email=data['email']).first()
        print(f"Found user: {user}")  # Debug print

        if not user or not check_password_hash(user.password, data['password']):
            print("Invalid credentials")  # Debug print
            return jsonify({'error': 'Incorrect email or password'}), 401

        # Clear and set new session
        session.clear()
        session['user_id'] = user.id
        session.modified = True
        print(f"Set session for user_id: {user.id}")  # Debug print

        response = make_response(jsonify({
            'message': 'Login successful',
            'user': {
                'email': user.email,
                'name': user.name
            }
        }))
        
        print("Sending successful response")  # Debug print
        return response, 200

    except Exception as e:
        print('Login error:', str(e))  # Debug print
        return jsonify({'error': 'An error occurred during login'}), 500

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

@app.route('/api/check-login', methods=['GET'])
def check_login():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return jsonify({'error': 'User not found'}), 401

    return jsonify({
        'message': 'Logged in',
        'user': {
            'email': user.email,
            'name': user.name
        }
    }), 200

if __name__ == '__main__':
    app.run(port=8000, debug=True) 