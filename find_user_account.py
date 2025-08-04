import sqlite3
from app import app, db, User, Organization
from datetime import datetime

def find_user_account(email=None, user_id=None):
    """Find a user account in the database"""
    with app.app_context():
        print("=== DATABASE QUERY TOOL ===")
        print()
        
        # Get total count of users
        total_users = User.query.count()
        print(f"Total users in database: {total_users}")
        print()
        
        if email:
            print(f"Searching for user with email: {email}")
            user = User.query.filter_by(email=email).first()
            if user:
                print("✅ USER FOUND!")
                print_user_details(user)
            else:
                print("❌ User not found with that email")
                print()
                print("Available users:")
                list_all_users()
        elif user_id:
            print(f"Searching for user with ID: {user_id}")
            user = User.query.get(user_id)
            if user:
                print("✅ USER FOUND!")
                print_user_details(user)
            else:
                print("❌ User not found with that ID")
        else:
            print("No specific search criteria provided. Listing all users:")
            print()
            list_all_users()
        
        print()
        print("=== ORGANIZATION INFO ===")
        total_orgs = Organization.query.count()
        print(f"Total organizations: {total_orgs}")
        
        orgs = Organization.query.all()
        for org in orgs:
            print(f"Organization ID: {org.id}, Name: {org.name}")
            org_users = User.query.filter_by(organization_id=org.id).count()
            print(f"  - Users in this org: {org_users}")

def print_user_details(user):
    """Print detailed user information"""
    print(f"ID: {user.id}")
    print(f"Email: {user.email}")
    print(f"First Name: {user.first_name}")
    print(f"Last Name: {user.last_name}")
    print(f"Preferred Name: {user.preferred_name}")
    print(f"Date of Birth: {user.date_of_birth}")
    print(f"Citizenship: {user.citizenship}")
    print(f"Phone: {user.phone}")
    print(f"Tax Residence: {user.tax_residence}")
    print(f"Worker External ID: {user.worker_external_id}")
    print(f"Seniority Level: {user.seniority_level}")
    print(f"Profile Completed: {user.profile_completed}")
    print(f"Organization ID: {user.organization_id}")
    print(f"Avatar URL: {user.avatar_url}")
    print(f"Worker Type ID: {user.worker_type_id}")
    print(f"Group ID: {user.group_id}")
    print(f"Country Code: {user.country_code}")
    print(f"Residence Country Code: {user.residence_country_code}")
    print(f"Schedule ID: {user.schedule_id}")
    print(f"Created At: {user.created_at}")
    print(f"Reset Token: {user.reset_token}")
    print(f"Reset Token Expiry: {user.reset_token_expiry}")

def list_all_users():
    """List all users in the database"""
    users = User.query.all()
    if not users:
        print("No users found in database")
        return
    
    print(f"{'ID':<5} {'Email':<30} {'Name':<25} {'Org ID':<8} {'Profile Complete':<15}")
    print("-" * 85)
    for user in users:
        name = user.name if user.name != "None" else "N/A"
        profile_status = "Yes" if user.profile_completed else "No"
        print(f"{user.id:<5} {user.email:<30} {name:<25} {user.organization_id or 'N/A':<8} {profile_status:<15}")

def check_database_schema():
    """Check the database schema to ensure tables exist"""
    with app.app_context():
        print("=== DATABASE SCHEMA CHECK ===")
        
        # Check if tables exist
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"Tables found: {tables}")
        
        if 'user' in tables:
            print("✅ User table exists")
            # Get column information
            columns = inspector.get_columns('user')
            print("User table columns:")
            for col in columns:
                print(f"  - {col['name']}: {col['type']}")
        else:
            print("❌ User table not found")
        
        if 'organization' in tables:
            print("✅ Organization table exists")
        else:
            print("❌ Organization table not found")

if __name__ == '__main__':
    print("HRM Database Query Tool")
    print("=" * 50)
    
    # Check database schema first
    check_database_schema()
    print()
    
    # Ask for search criteria
    print("Search options:")
    print("1. Search by email")
    print("2. Search by user ID")
    print("3. List all users")
    print("4. Exit")
    
    choice = input("\nEnter your choice (1-4): ").strip()
    
    if choice == '1':
        email = input("Enter email address: ").strip()
        find_user_account(email=email)
    elif choice == '2':
        try:
            user_id = int(input("Enter user ID: ").strip())
            find_user_account(user_id=user_id)
        except ValueError:
            print("Invalid user ID. Please enter a number.")
    elif choice == '3':
        find_user_account()
    elif choice == '4':
        print("Exiting...")
    else:
        print("Invalid choice. Running default search...")
        find_user_account() 