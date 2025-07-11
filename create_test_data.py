from app import app, db, User, Organization, WorkerType
from werkzeug.security import generate_password_hash
from datetime import datetime

def create_test_data():
    with app.app_context():
        # Create a test organization
        org = Organization(
            name="Test Organization",
            industry="Technology",
            size="10-50",
            location="Test City"
        )
        db.session.add(org)
        db.session.flush()  # Get the org ID
        
        # Create a test user
        user = User(
            email="test@example.com",
            password=generate_password_hash("password123"),
            first_name="Test",
            last_name="User",
            organization_id=org.id,
            profile_completed=True
        )
        db.session.add(user)
        db.session.flush()  # Get the user ID
        
        # Create some test worker types
        worker_types = [
            WorkerType(
                template_name="Software Developer",
                description="Develops and maintains software applications",
                organization_id=org.id,
                created_by=user.id
            ),
            WorkerType(
                template_name="Project Manager",
                description="Manages project timelines and resources",
                organization_id=org.id,
                created_by=user.id
            ),
            WorkerType(
                template_name="Designer",
                description="Creates user interfaces and user experiences",
                organization_id=org.id,
                created_by=user.id
            )
        ]
        
        for wt in worker_types:
            db.session.add(wt)
        
        db.session.commit()
        print("Test data created successfully!")
        print(f"Organization: {org.name} (ID: {org.id})")
        print(f"User: {user.email} (ID: {user.id})")
        print(f"Worker types created: {len(worker_types)}")

if __name__ == '__main__':
    create_test_data() 