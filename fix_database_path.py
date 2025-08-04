import os
import shutil
from app import app, db, User, Organization

def fix_database_connection():
    """Fix the database connection to use the correct users.db file"""
    print("=== FIXING DATABASE CONNECTION ===")
    print()
    
    # Get current working directory
    current_dir = os.getcwd()
    main_db_path = os.path.join(current_dir, 'users.db')
    instance_db_path = os.path.join(current_dir, 'instance', 'users.db')
    
    print(f"Current directory: {current_dir}")
    print(f"Main database: {main_db_path}")
    print(f"Instance database: {instance_db_path}")
    print()
    
    # Check file sizes
    if os.path.exists(main_db_path):
        main_size = os.path.getsize(main_db_path)
        print(f"Main database size: {main_size} bytes")
    
    if os.path.exists(instance_db_path):
        instance_size = os.path.getsize(instance_db_path)
        print(f"Instance database size: {instance_size} bytes")
    
    print()
    
    # The main database has your data, so let's copy it to the instance folder
    if os.path.exists(main_db_path) and os.path.exists(instance_db_path):
        print("✅ Found both database files")
        print("📋 Copying main database to instance folder...")
        
        # Backup the instance database first
        backup_path = instance_db_path + '.backup'
        shutil.copy2(instance_db_path, backup_path)
        print(f"📦 Backed up instance database to: {backup_path}")
        
        # Copy the main database to instance
        shutil.copy2(main_db_path, instance_db_path)
        print("✅ Copied main database to instance folder")
        
        # Verify the copy
        new_instance_size = os.path.getsize(instance_db_path)
        print(f"New instance database size: {new_instance_size} bytes")
        
        if new_instance_size == main_size:
            print("✅ Database copy successful!")
        else:
            print("❌ Database copy failed!")
            
    elif os.path.exists(main_db_path):
        print("✅ Found main database, creating instance folder...")
        os.makedirs(os.path.dirname(instance_db_path), exist_ok=True)
        shutil.copy2(main_db_path, instance_db_path)
        print("✅ Copied main database to instance folder")
    else:
        print("❌ Main database not found!")
        return
    
    print()
    print("=== VERIFYING FIX ===")
    
    # Test the connection with the fixed database
    with app.app_context():
        try:
            user_count = User.query.count()
            org_count = Organization.query.count()
            print(f"✅ Users in database: {user_count}")
            print(f"✅ Organizations in database: {org_count}")
            
            # Check for your specific account
            user = User.query.filter_by(email='duyphudang2007@gmail.com').first()
            if user:
                print(f"✅ Found your account: {user.email} (ID: {user.id})")
                print("🎉 Database connection fixed successfully!")
            else:
                print("❌ Your account still not found")
                
        except Exception as e:
            print(f"❌ Error testing connection: {e}")
    
    print()
    print("=== NEXT STEPS ===")
    print("1. Restart your Flask application: python app.py")
    print("2. Try logging in again with your email and password")
    print("3. Your account should now be visible in the web interface")

if __name__ == '__main__':
    fix_database_connection() 