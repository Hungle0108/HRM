from app import app, db, User, Organization

def detailed_user_check():
    with app.app_context():
        print("=== DETAILED USER DATABASE CHECK ===")
        print()
        
        # Get all users
        users = User.query.all()
        
        if not users:
            print("❌ No users found in database!")
            return
        
        print(f"✅ Found {len(users)} user(s) in database:")
        print()
        
        for i, user in enumerate(users, 1):
            print(f"--- USER #{i} ---")
            print(f"ID: {user.id}")
            print(f"Email: {user.email}")
            print(f"First Name: {user.first_name}")
            print(f"Last Name: {user.last_name}")
            print(f"Preferred Name: {user.preferred_name}")
            print(f"Profile Completed: {user.profile_completed}")
            print(f"Organization ID: {user.organization_id}")
            print(f"Created At: {user.created_at}")
            print(f"Phone: {user.phone}")
            print(f"Date of Birth: {user.date_of_birth}")
            print(f"Citizenship: {user.citizenship}")
            print(f"Worker Type ID: {user.worker_type_id}")
            print(f"Group ID: {user.group_id}")
            print(f"Schedule ID: {user.schedule_id}")
            print()
        
        print("=== ORGANIZATIONS ===")
        orgs = Organization.query.all()
        if orgs:
            for org in orgs:
                print(f"Organization ID: {org.id}")
                print(f"Name: {org.name}")
                print(f"Industry: {org.industry}")
                print(f"Size: {org.size}")
                print(f"Location: {org.location}")
                print(f"Created At: {org.created_at}")
                print()
        else:
            print("No organizations found")
        
        print("=== DATABASE SUMMARY ===")
        print(f"Total Users: {User.query.count()}")
        print(f"Total Organizations: {Organization.query.count()}")
        print(f"Users with completed profiles: {User.query.filter_by(profile_completed=True).count()}")
        print(f"Users without organizations: {User.query.filter_by(organization_id=None).count()}")

if __name__ == '__main__':
    detailed_user_check() 