from flask import Flask, request, jsonify, send_from_directory, redirect, session, make_response, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from flask_mail import Mail, Message
import secrets
import logging
import ssl
import traceback
import base64
import urllib.parse

app = Flask(__name__)

# Set up logging with more details
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'duyphudang2007@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'dhrabdlbhitzegbd')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME', 'duyphudang2007@gmail.com')
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_ASCII_ATTACHMENTS'] = False

# Initialize SQLAlchemy with the app
db = SQLAlchemy()
db.init_app(app)

# Initialize Flask-Mail
mail = Mail(app)

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
    avatar_url = db.Column(db.String(255))
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)

    @property
    def name(self):
        if self.preferred_name:
            return self.preferred_name
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
            'organization_id': self.organization_id,
            'avatar_url': self.avatar_url
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
    groups = db.relationship('Group', backref='organization', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'industry': self.industry,
            'size': self.size,
            'location': self.location,
            'logo_url': self.logo_url
        }

# Group model
class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), default='ACTIVE')
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    admin_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contracts_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    admin_user = db.relationship('User', backref='administered_groups')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'status': self.status,
            'organization_id': self.organization_id,
            'admin_user_id': self.admin_user_id,
            'contracts_count': self.contracts_count,
            'admin_name': self.admin_user.name if self.admin_user else None,
            'admin_email': self.admin_user.email if self.admin_user else None
        }

# Organization Structure Model
class OrgStructure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    allow_multiple_assignments = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    organization = db.relationship('Organization', backref='structures')
    items = db.relationship('StructureItem', backref='structure', lazy='dynamic', cascade="all, delete-orphan")

# Structure Item Model
class StructureItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    level = db.Column(db.Integer, nullable=False)
    structure_id = db.Column(db.Integer, db.ForeignKey('org_structure.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('structure_item.id'))
    
    children = db.relationship('StructureItem', backref=db.backref('parent', remote_side=[id]), cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'level': self.level,
            'parent_id': self.parent_id,
            'children': [child.to_dict() for child in self.children]
        }

# Create database tables
def init_db():
    with app.app_context():
        # Drop all tables first to ensure clean state
        db.drop_all()
        # Create all tables
        db.create_all()
        print("Database initialized successfully!")

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

@app.route('/members')
def members():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    organization = None
    if user.organization_id:
        organization = Organization.query.get(user.organization_id)
    
    return render_template('members.html', user=user, organization=organization)

@app.route('/add-people')
def add_people():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('add_people.html', user=user)

@app.route('/add-employee')
def add_employee():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    organization = None
    user_groups = []
    structure_data = []
    if user.organization_id:
        organization = Organization.query.get(user.organization_id)
        user_groups = Group.query.filter_by(organization_id=user.organization_id).all()
        
        structures = OrgStructure.query.filter_by(organization_id=user.organization_id).all()
        for structure in structures:
            # Fetch top-level items for each structure
            top_level_items = StructureItem.query.filter_by(structure_id=structure.id, parent_id=None).all()
            structure_dict = {
                'id': structure.id,
                'name': structure.name,
                'allow_multiple_assignments': structure.allow_multiple_assignments,
                'items': [item.to_dict() for item in top_level_items]
            }
            print(f"DEBUG: Structure {structure.name} - items type: {type(structure_dict['items'])}, items: {structure_dict['items']}")
            structure_data.append(structure_dict)
        
        print(f"DEBUG: Total structure_data: {len(structure_data)}")
        print(f"DEBUG: Type of structure_data: {type(structure_data)}")
    
    return render_template('add_employee.html', user=user, organization=organization, groups=user_groups, org_structures=structure_data)

@app.route('/add-employee-step2')
def add_employee_step2():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('add_employee_step2.html', user=user)

@app.route('/add-employee-step3')
def add_employee_step3():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('add_employee_step3.html', user=user)

@app.route('/add-employee-step4')
def add_employee_step4():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('add_employee_step4.html', user=user)

@app.route('/add-employee-step5')
def add_employee_step5():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('add_employee_step5.html', user=user)

@app.route('/add-employee-step6')
def add_employee_step6():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('add_employee_step6.html', user=user)

@app.route('/add-contractor')
def add_contractor():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('add_contractor.html', user=user)

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

        # Check if email exists first
        if not user:
            print("Email does not exist")  # Debug print
            return jsonify({'error': 'Email does not exist'}), 404

        # Then check password
        if not check_password_hash(user.password, data['password']):
            print("Invalid password")  # Debug print
            return jsonify({'error': 'Incorrect password'}), 401

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

@app.route('/logout', methods=['GET'])
def logout_get():
    # Clear the session
    session.clear()
    return redirect('/login')

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
    return render_template('organization_details.html', user=user, organization=organization, active_page='organization_details')

@app.route('/groups')
def groups():
    if 'user_id' not in session:
        return redirect('/login')
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    organization = None
    user_groups = []
    if user.organization_id:
        organization = Organization.query.get(user.organization_id)
        # Get all groups for this organization
        user_groups = Group.query.filter_by(organization_id=user.organization_id).all()
    return render_template('groups.html', user=user, organization=organization, groups=user_groups, active_page='groups')

@app.route('/create-office')
def create_office():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    organization = None
    if user.organization_id:
        organization = Organization.query.get(user.organization_id)
    
    return render_template('create_office.html', user=user, organization=organization)

@app.route('/create-office-step2')
def create_office_step2():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    organization = None
    if user.organization_id:
        organization = Organization.query.get(user.organization_id)
    
    return render_template('create_office_step2.html', user=user, organization=organization)

@app.route('/create-office-step3')
def create_office_step3():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    organization = None
    if user.organization_id:
        organization = Organization.query.get(user.organization_id)
    
    return render_template('create_office_step3.html', user=user, organization=organization)

@app.route('/api/create-group', methods=['POST'])
def create_group():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or not user.organization_id:
        return jsonify({'error': 'User not found or no organization'}), 400
    
    data = request.get_json()
    group_name = data.get('groupName')
    
    if not group_name:
        return jsonify({'error': 'Group name is required'}), 400
    
    try:
        # Create new group with the user as the admin
        new_group = Group(
            name=group_name,
            status='ACTIVE',
            organization_id=user.organization_id,
            admin_user_id=user.id,
            contracts_count=0
        )
        
        db.session.add(new_group)
        db.session.commit()
        
        return jsonify({
            'message': 'Group created successfully',
            'group': new_group.to_dict(),
            'redirect': '/groups'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create group'}), 500

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
def complete_profile():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    if user.profile_completed:
        return redirect('/dashboard')
        
    # Get stored profile data from session
    profile_data = session.get('profile_data', {})
        
    return render_template('complete_profile.html', user=user, profile_data=profile_data)

@app.route('/api/complete-profile', methods=['POST'])
def submit_complete_profile():
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
    if not user:
        session.pop('user_id', None)
        return redirect('/login')

    if user.organization_id:
        return redirect('/dashboard')

    # Get stored organization data from session
    organization_data = session.get('organization_data', {})
    
    return render_template('organization_setup.html', organization_data=organization_data, user=user)

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
    if not user:
        session.pop('user_id', None)
        return redirect('/login')

    if user.organization_id:
        return redirect('/dashboard')

    # Get stored size data from session
    size_data = session.get('size_data', {})
    
    return render_template('people_count.html', size_data=size_data, user=user)

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

@app.route('/profile')
def profile():
    return redirect('/profile/settings')

@app.route('/profile/settings')
def profile_settings():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('profile_settings.html', user=user)

@app.route('/profile/account-access')
def profile_account_access():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    organization = None
    if user.organization_id:
        organization = Organization.query.get(user.organization_id)
    
    return render_template('profile_account_access.html', user=user, organization=organization)

@app.route('/profile/edit-personal-details')
def edit_personal_details():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('edit_personal_details.html', user=user)

@app.route('/api/update-personal-details', methods=['POST'])
def update_personal_details():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    
    try:
        # Update user fields
        if 'first_name' in data:
            user.first_name = data['first_name']
        if 'last_name' in data:
            user.last_name = data['last_name']
        if 'preferred_name' in data:
            user.preferred_name = data['preferred_name']
        if 'date_of_birth' in data:
            user.date_of_birth = data['date_of_birth']
        if 'citizenship' in data:
            user.citizenship = data['citizenship']
        if 'phone' in data:
            user.phone = data['phone']
        if 'tax_residence' in data:
            user.tax_residence = data['tax_residence']
            
        db.session.commit()
        return jsonify({'message': 'Personal details updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update personal details'}), 500

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return redirect('/')

@app.route('/organization/edit')
def edit_organization():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    organization = None
    if user.organization_id:
        organization = Organization.query.get(user.organization_id)
    
    return render_template('edit_organization.html', user=user, organization=organization)

@app.route('/financial-contact/edit')
def edit_financial_contact():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('edit_financial_contact.html', user=user)

@app.route('/api/upload-avatar', methods=['POST'])
def upload_avatar():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    if 'avatar' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.content_type.startswith('image/'):
        return jsonify({'error': 'File must be an image'}), 400

    try:
        # Create uploads directory if it doesn't exist
        upload_dir = os.path.join(app.root_path, 'static', 'uploads', 'avatars')
        os.makedirs(upload_dir, exist_ok=True)

        # Generate unique filename
        filename = f"avatar_{session['user_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{os.path.splitext(file.filename)[1]}"
        filepath = os.path.join(upload_dir, filename)

        # Save the file
        file.save(filepath)

        # Update user's avatar_url in database
        user = User.query.get(session['user_id'])
        if user.avatar_url:
            # Delete old avatar file if it exists
            old_filepath = os.path.join(app.root_path, 'static', user.avatar_url.lstrip('/'))
            if os.path.exists(old_filepath):
                os.remove(old_filepath)

        user.avatar_url = f"/static/uploads/avatars/{filename}"
        db.session.commit()

        return jsonify({
            'message': 'Avatar uploaded successfully',
            'avatar_url': user.avatar_url
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to upload avatar'}), 500

@app.route('/api/remove-avatar', methods=['POST'])
def remove_avatar():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    try:
        user = User.query.get(session['user_id'])
        if user.avatar_url:
            # Delete avatar file
            filepath = os.path.join(app.root_path, 'static', user.avatar_url.lstrip('/'))
            if os.path.exists(filepath):
                os.remove(filepath)

            # Clear avatar_url in database
            user.avatar_url = None
            db.session.commit()

        return jsonify({'message': 'Avatar removed successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to remove avatar'}), 500

@app.route('/api/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Both current and new passwords are required', 'field': 'general'}), 400
        
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'error': 'User not found', 'field': 'general'}), 404
        
        # Verify current password
        if not check_password_hash(user.password, current_password):
            return jsonify({'error': 'Current password is incorrect', 'field': 'current_password'}), 400
        
        # Validate new password requirements
        if len(new_password) < 10 or len(new_password) > 70:
            return jsonify({'error': 'Password must be between 10 and 70 characters', 'field': 'new_password'}), 400
        
        if not any(c.isupper() for c in new_password):
            return jsonify({'error': 'Password must contain at least one uppercase letter', 'field': 'new_password'}), 400
        
        if not any(c.islower() for c in new_password):
            return jsonify({'error': 'Password must contain at least one lowercase letter', 'field': 'new_password'}), 400
        
        if not any(c.isdigit() for c in new_password):
            return jsonify({'error': 'Password must contain at least one number', 'field': 'new_password'}), 400
        
        # Check for special characters
        special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        if not any(c in special_chars for c in new_password):
            return jsonify({'error': 'Password must contain at least one special character', 'field': 'new_password'}), 400
        
        # Check if new password is the same as current password
        if check_password_hash(user.password, new_password):
            return jsonify({'error': 'New password must be different from your current password', 'field': 'new_password'}), 400
        
        # Update password
        user.password = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error changing password: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while changing password', 'field': 'general'}), 500

@app.route('/reset-password')
def reset_password_page():
    return render_template('reset_password.html')

@app.route('/check-inbox')
def check_inbox():
    email = request.args.get('email', '')
    return render_template('check_inbox.html', email=email)

@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'error': 'Please enter your email'}), 400

        # Log email configuration
        logger.info("Email Configuration:")
        logger.info(f"MAIL_SERVER: {app.config['MAIL_SERVER']}")
        logger.info(f"MAIL_PORT: {app.config['MAIL_PORT']}")
        logger.info(f"MAIL_USE_TLS: {app.config['MAIL_USE_TLS']}")
        logger.info(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
        logger.info(f"Attempting to send email to: {email}")

        # Verify SMTP connection first
        try:
            with app.app_context():
                with mail.connect() as conn:
                    logger.info("SMTP connection test successful")
        except Exception as smtp_error:
            logger.error(f"SMTP connection error: {str(smtp_error)}")
            return jsonify({'error': 'Failed to connect to email server. Please try again.'}), 500

        user = User.query.filter_by(email=email).first()
        if not user:
            logger.info(f"No user found with email: {email}")
            return jsonify({'error': 'Email does not exist'}), 404

        # Generate a secure token and encode it as URL-safe base64
        token = secrets.token_urlsafe(32)
        user.reset_token = token
        user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)

        try:
            # Save the token to the database
            db.session.commit()
            logger.info(f"Generated reset token for user: {email}")

            # Create the email message with URL-safe token
            reset_link = f"http://{request.host}/reset-password/{urllib.parse.quote(token)}"
            
            # Prepare email HTML
            email_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{
                        margin: 0;
                        padding: 0;
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                        background-color: #ffffff;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 0 auto;
                        background-color: #FFE169;
                        padding: 40px;
                    }}
                    .content {{
                        text-align: center;
                    }}
                    h1 {{
                        font-size: 24px;
                        color: #1a1a1a;
                        margin-bottom: 20px;
                    }}
                    p {{
                        color: #1a1a1a;
                        margin-bottom: 30px;
                        font-size: 16px;
                    }}
                    .button {{
                        display: inline-block;
                        background-color: #1a1a1a;
                        color: white !important;
                        text-decoration: none;
                        padding: 12px 24px;
                        border-radius: 20px;
                        font-size: 16px;
                        margin: 20px 0;
                    }}
                    .footer {{
                        margin-top: 30px;
                        font-size: 14px;
                        color: #1a1a1a;
                    }}
                    .chat-link {{
                        color: #1a1a1a;
                        text-decoration: underline;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="content">
                        <h1>Reset your password</h1>
                        <p>Just click the button below to set your password.</p>
                        <a href="{reset_link}" class="button" style="color: white !important;">Reset password</a>
                        <p>If you weren't expecting this email, please ignore this message.</p>
                        <div class="footer">
                            <p>Have a question? Reach out to us on <a href="#" class="chat-link">chat</a></p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """

            # Create and send the email
            with app.app_context():
                msg = Message(
                    subject='Reset your password',
                    recipients=[email],
                    html=email_html,
                    sender=app.config['MAIL_DEFAULT_SENDER']
                )
                mail.send(msg)
                logger.info(f"Email sent successfully to {email}")

            return jsonify({'message': 'If your email is registered, you will receive reset instructions'}), 200

        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            db.session.rollback()
            return jsonify({'error': 'Failed to send reset email. Please try again.'}), 500

    except Exception as e:
        logger.error(f"General error in password reset: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'An error occurred. Please try again.'}), 500

@app.route('/reset-password/<token>')
def reset_password_with_token(token):
    try:
        # URL decode the token
        decoded_token = urllib.parse.unquote(token)
        user = User.query.filter_by(reset_token=decoded_token).first()
        
        if not user or not user.reset_token_expiry or user.reset_token_expiry < datetime.utcnow():
            return render_template('new_password.html', token=token, error='Invalid or expired reset link. Please request a new one.')
        
        return render_template('new_password.html', token=token)
    except Exception as e:
        logger.error(f"Error in reset_password_with_token: {str(e)}")
        return render_template('new_password.html', token=token, error='Invalid reset link format. Please request a new one.')

@app.route('/api/reset-password/<token>', methods=['POST'])
def reset_password(token):
    try:
        # URL decode the token
        decoded_token = urllib.parse.unquote(token)
        user = User.query.filter_by(reset_token=decoded_token).first()
        
        if not user or not user.reset_token_expiry or user.reset_token_expiry < datetime.utcnow():
            return jsonify({'error': 'Invalid or expired reset link'}), 400

        data = request.get_json()
        new_password = data.get('password')
        
        if not new_password:
            return jsonify({'error': 'Please enter a new password'}), 400

        try:
            # Check if the new password is the same as the old one
            if check_password_hash(user.password, new_password):
                return jsonify({'error': 'Your new password must not be the same as your previous one'}), 400

            user.password = generate_password_hash(new_password)
            user.reset_token = None
            user.reset_token_expiry = None
            db.session.commit()
            
            return jsonify({'message': 'Password reset successful'}), 200
        except Exception as e:
            logger.error(f"Error resetting password: {str(e)}")
            db.session.rollback()
            return jsonify({'error': 'Failed to reset password'}), 500
    except Exception as e:
        logger.error(f"Error in reset_password: {str(e)}")
        return jsonify({'error': 'Invalid reset link format'}), 400

@app.route('/language-settings')
def language_settings():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('language_settings.html', user=user)

@app.route('/settings/entities')
def settings_entities():
    if 'user_id' not in session:
        return redirect('/login')
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    organization = None
    if user.organization_id:
        organization = Organization.query.get(user.organization_id)
    return render_template('entities.html', user=user, organization=organization, active_page='entities')

@app.route('/settings/org-chart')
def org_chart():
    if 'user_id' not in session:
        return redirect('/login')
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    organization = None
    structures = []
    if user.organization_id:
        organization = Organization.query.get(user.organization_id)
        # Fetch all structures for this organization
        structures = OrgStructure.query.filter_by(organization_id=user.organization_id).all()
    return render_template('org_chart.html', user=user, organization=organization, structures=structures, active_page='org_chart')

@app.route('/settings/create-structure')
def create_structure():
    if 'user_id' not in session:
        return redirect('/login')
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    organization = None
    if user.organization_id:
        organization = Organization.query.get(user.organization_id)
    return render_template('create_structure.html', user=user, organization=organization)

@app.route('/api/create-structure', methods=['POST'])
def api_create_structure():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user = User.query.get(session['user_id'])
    if not user or not user.organization_id:
        return jsonify({'error': 'User or organization not found'}), 400

    data = request.get_json()
    structure_name = data.get('name')
    allow_multiple = data.get('allowMultiple')
    items = data.get('items', [])

    if not structure_name or not items:
        return jsonify({'error': 'Structure name and at least one item are required'}), 400

    try:
        # Create the main structure
        new_structure = OrgStructure(
            name=structure_name,
            organization_id=user.organization_id,
            allow_multiple_assignments=allow_multiple
        )
        db.session.add(new_structure)
        db.session.flush()  # Flush to get the new_structure.id for items

        parent_stack = []  # Stack to keep track of parent items by level

        for item_data in items:
            level = item_data['level']
            item_name = item_data['name']

            # Find the correct parent for the current item
            while parent_stack and parent_stack[-1]['level'] >= level:
                parent_stack.pop()

            parent_id = parent_stack[-1]['item'].id if parent_stack else None

            # Create the new structure item
            new_item = StructureItem(
                name=item_name,
                level=level,
                structure_id=new_structure.id,
                parent_id=parent_id
            )
            db.session.add(new_item)
            db.session.flush() # Flush to get the new_item.id

            # Push the current item to the stack for potential children
            parent_stack.append({'level': level, 'item': new_item})

        db.session.commit()
        return jsonify({'message': 'Structure created successfully', 'redirect': '/settings/org-chart'}), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating structure: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to create structure'}), 500

@app.route('/settings/time-tracking')
def time_tracking():
    """Time tracking settings page"""
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        return redirect('/login')
    
    # Get the user's organization
    organization = None
    if user.organization_id:
        organization = Organization.query.get(user.organization_id)
    
    return render_template('time_tracking.html', user=user, organization=organization, active_page='time_tracking')

@app.route('/create-schedule')
def create_schedule():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('create_schedule.html', user=user)

@app.route('/create-schedule-step2')
def create_schedule_step2():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect('/login')
    
    return render_template('create_schedule_step2.html', user=user)

if __name__ == '__main__':
    with app.app_context():
        init_db()  # Initialize database tables before running
    app.run(port=8000, debug=True) 