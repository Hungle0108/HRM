from app import app, db, User, Organization

def check_all_users():
    with app.app_context():
        print("=== HRM DATABASE USERS ===")
        print()
        
        # Get all users
        users = User.query.all()
        
        if not users:
            print("❌ No users found in database!")
            print("Possible reasons:")
            print("1. Database is empty")
            print("2. You haven't registered an account yet")
            print("3. Database was reset/cleared")
            return
        
        print(f"✅ Found {len(users)} user(s) in database:")
        print()
        print(f"{'ID':<5} {'Email':<35} {'Name':<25} {'Org ID':<8} {'Profile Complete':<15}")
        print("-" * 90)
        
        for user in users:
            name = user.name if user.name != "None" else "N/A"
            profile_status = "Yes" if user.profile_completed else "No"
            org_id = str(user.organization_id) if user.organization_id else "N/A"
            print(f"{user.id:<5} {user.email:<35} {name:<25} {org_id:<8} {profile_status:<15}")
        
        print()
        print("=== ORGANIZATIONS ===")
        orgs = Organization.query.all()
        if orgs:
            for org in orgs:
                org_users = User.query.filter_by(organization_id=org.id).count()
                print(f"Organization: {org.name} (ID: {org.id}) - {org_users} users")
        else:
            print("No organizations found")
        
        print()
        print("=== TROUBLESHOOTING TIPS ===")
        print("If you can't find your account:")
        print("1. Make sure you registered with the correct email")
        print("2. Check if you completed the registration process")
        print("3. Try logging in through the web interface")
        print("4. If you're sure you registered, the account might be in a different database file")

if __name__ == '__main__':
    check_all_users() 