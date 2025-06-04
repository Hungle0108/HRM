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

# Initialize SQLAlchemy with the app
db = SQLAlchemy()
db.init_app(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    preferred_name = db.Column(db.String(80))
    date_of_birth = db.Column(db.String(20))
    citizenship = db.Column(db.String(80))
    phone = db.Column(db.String(20))
    tax_residence = db.Column(db.String(80))
    department = db.Column(db.String(80))
    job_title = db.Column(db.String(80))
    seniority_level = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_completed = db.Column(db.Boolean, default=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'))
    organization = db.relationship('Organization')

    @property
    def name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return "None"

    def __repr__(self):
        return f'<User {self.email}>'

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'preferred_name': self.preferred_name,
            'date_of_birth': self.date_of_birth,
            'citizenship': self.citizenship,
            'phone': self.phone,
            'tax_residence': self.tax_residence,
            'department': self.department,
            'job_title': self.job_title,
            'seniority_level': self.seniority_level,
            'organization_id': self.organization_id
        }

# Organization model
class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    industry = db.Column(db.String(80))
    size = db.Column(db.String(50))
    location = db.Column(db.String(120))
    logo_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    users = db.relationship('User', backref='org', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'industry': self.industry,
            'size': self.size,
            'location': self.location,
            'logo_url': self.logo_url
        }

# Create database tables
def init_db():
    with app.app_context():
        # Drop all tables first to ensure clean state
        db.drop_all()
        # Create all tables
        db.create_all()
        print("Database initialized successfully!")

# Initialize the database before first request
@app.before_first_request
def create_tables():
    init_db()

# Serve static files
@app.route('/')
def home():
    print("Accessing home route")
    if 'user_id' not in session:
        print("No user_id in session, redirecting to login")
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    print("User is logged in, serving home.html")
    return render_template('home.html', user=user)

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect('/')
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    if 'user_id' in session:
        return redirect('/')
    return render_template('signup.html')

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
    # Clear the session
    session.clear()
    return jsonify({'message': 'Logged out successfully', 'redirect': '/login'}), 200

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

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    organization = None
    if user.organization_id:
        organization = Organization.query.get(user.organization_id)
    
    return render_template('settings.html', user=user, organization=organization)

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('firstName', '').strip()
    last_name = data.get('lastName', '').strip()

    if not email or not password:
        return jsonify({'error': 'Please enter both email and password'}), 400

    if not first_name or not last_name:
        return jsonify({'error': 'Please enter both first and last name'}), 400

    # Capitalize first letter of first and last name
    first_name = first_name.capitalize()
    last_name = last_name.capitalize()

    # Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'Email already registered'}), 400

    # Create new user
    hashed_password = generate_password_hash(password)
    new_user = User(
        email=email, 
        password=hashed_password,
        first_name=first_name,
        last_name=last_name,
        profile_completed=False
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id
        return jsonify({
            'message': 'Signup successful',
            'redirect': '/complete-profile'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'An error occurred during signup'}), 500

@app.route('/api/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Please enter an email'}), 400

    # Check if user exists
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Email does not exist'}), 404

    return jsonify({'message': 'Email exists'}), 200

@app.route('/complete-profile')
def complete_profile_page():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    if user.profile_completed:
        return redirect('/')
        
    # Get stored profile data if it exists
    profile_data = session.get('profile_data', {})
        
    return render_template('complete_profile.html', user=user, profile_data=profile_data)

@app.route('/api/complete-profile', methods=['POST'])
def complete_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    
    if not data or not all(key in data for key in ['citizenship', 'dateOfBirth', 'phoneNumber']):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        # Store profile data in session
        session['profile_data'] = {
            'citizenship': data['citizenship'],
            'date_of_birth': data['dateOfBirth'],
            'phone_number': data['phoneNumber']
        }
        return jsonify({
            'message': 'Profile data stored',
            'redirect': '/organization-setup'
        }), 200
    except Exception as e:
        return jsonify({'error': 'Failed to store profile data'}), 500

@app.route('/organization-setup')
def organization_setup():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if user.organization_id:
        return redirect('/dashboard')

    # Get stored organization data if it exists    
    organization_data = session.get('organization_data', {})
    
    return render_template('organization_setup.html', organization_data=organization_data)

@app.route('/api/setup-organization', methods=['POST'])
def setup_organization():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    
    if not data or not all(key in data for key in ['organizationName', 'location']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        # Store organization data in session
        session['organization_data'] = {
            'name': data['organizationName'],
            'location': data['location']
        }
        return jsonify({
            'message': 'Organization data stored',
            'redirect': '/people-count'
        }), 200
    except Exception as e:
        return jsonify({'error': 'Failed to store organization data'}), 500

@app.route('/people-count')
def people_count():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if user.organization_id:
        return redirect('/dashboard')

    # Get stored size data if it exists    
    size_data = session.get('size_data', {})
    
    return render_template('people_count.html', size_data=size_data)

@app.route('/api/update-organization-size', methods=['POST'])
def update_organization_size():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    
    if not data or 'size' not in data:
        return jsonify({'error': 'Missing size field'}), 400

    try:
        # Store size data in session first
        session['size_data'] = {
            'size': data['size']
        }

        # Only create organization and update user if this is final submission
        if data.get('isSubmitting', True):  # Default to True for backward compatibility
            # Create new organization with all the stored data
            org = Organization(
                name=session['organization_data']['name'],
                location=session['organization_data']['location'],
                size=data['size']
            )
            db.session.add(org)
            
            # Update user with all the stored data
            user = User.query.get(session['user_id'])
            user.citizenship = session['profile_data']['citizenship']
            user.date_of_birth = datetime.strptime(session['profile_data']['date_of_birth'], '%Y-%m-%d').date()
            user.phone_number = session['profile_data']['phone_number']
            user.organization_id = org.id
            user.profile_completed = True
            
            # Commit all changes to database
            db.session.commit()

            # Clear temporary session data after successful commit
            session.pop('profile_data', None)
            session.pop('organization_data', None)
            session.pop('size_data', None)

            return jsonify({
                'message': 'Setup completed successfully',
                'redirect': '/dashboard'
            }), 200
        else:
            # If not final submission, just store the data and return success
            return jsonify({
                'message': 'Size data stored',
                'redirect': None
            }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to complete setup'}), 500

@app.route('/api/update-organization-settings', methods=['POST'])
def update_organization_settings():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user = User.query.get(session['user_id'])
    if not user or not user.organization_id:
        return jsonify({'error': 'No organization found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        organization = Organization.query.get(user.organization_id)
        
        # Update organization fields
        if 'name' in data:
            organization.name = data['name']
        if 'location' in data:
            organization.location = data['location']
        if 'size' in data:
            organization.size = data['size']
            
        db.session.commit()
        return jsonify({'message': 'Organization settings updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update organization settings'}), 500

# Add context processor for organization data
@app.context_processor
def inject_organization():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.organization_id:
            organization = Organization.query.get(user.organization_id)
            return {'organization': organization}
    return {'organization': None}

@app.route('/profile/settings')
def profile_settings():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('profile_settings.html', user=user)

if __name__ == '__main__':
    with app.app_context():
        init_db()  # Initialize database tables before running
    app.run(port=8000, debug=True) 