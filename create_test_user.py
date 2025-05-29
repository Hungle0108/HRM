from app import app, db, User
from werkzeug.security import generate_password_hash

# Test user credentials
test_email = "test@example.com"
test_password = "password123"
test_name = "Test User"

with app.app_context():
    # Check if user already exists
    existing_user = User.query.filter_by(email=test_email).first()
    
    if existing_user:
        print(f"User {test_email} already exists!")
    else:
        # Create new test user
        new_user = User(
            email=test_email,
            password=generate_password_hash(test_password),
            name=test_name
        )
        
        # Add to database
        db.session.add(new_user)
        db.session.commit()
        print(f"Test user created successfully!")
        print(f"Email: {test_email}")
        print(f"Password: {test_password}") 