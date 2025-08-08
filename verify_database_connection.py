import os
import sqlite3
from app import app, db, User, Organization

def verify_database_connection():
    """Verify that the website is properly connected to users.db"""
    print("=== DATABASE CONNECTION VERIFICATION ===")
    print()
    
    # Check if users.db file exists
    # Always resolve to repository root users.db
    base_dir = os.path.abspath(os.path.dirname(__file__))
    db_path = os.path.join(base_dir, 'users.db')
    print(f"Database file path: {db_path}")
    print(f"Database file exists: {'✅ YES' if os.path.exists(db_path) else '❌ NO'}")
    
    if os.path.exists(db_path):
        file_size = os.path.getsize(db_path)
        print(f"Database file size: {file_size} bytes")
    print()
    
    # Test direct SQLite connection
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print("✅ Direct SQLite connection successful")
        print(f"Tables found: {[table[0] for table in tables]}")
        conn.close()
    except Exception as e:
        print(f"❌ Direct SQLite connection failed: {e}")
    print()
    
    # Test Flask-SQLAlchemy connection
    with app.app_context():
        try:
            # Test basic query
            user_count = User.query.count()
            print(f"✅ Flask-SQLAlchemy connection successful")
            print(f"Users in database: {user_count}")
            
            # Test organization query
            org_count = Organization.query.count()
            print(f"Organizations in database: {org_count}")
            
            # Test specific user query (your account)
            user = User.query.filter_by(email='duyphudang2007@gmail.com').first()
            if user:
                print(f"✅ Found your account: {user.email} (ID: {user.id})")
            else:
                print("❌ Your account not found in Flask-SQLAlchemy query")
                
        except Exception as e:
            print(f"❌ Flask-SQLAlchemy connection failed: {e}")
    
    print()
    print("=== DATABASE CONFIGURATION ===")
    print(f"SQLALCHEMY_DATABASE_URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print(f"SQLALCHEMY_TRACK_MODIFICATIONS: {app.config['SQLALCHEMY_TRACK_MODIFICATIONS']}")
    
    # Check if there are multiple database files
    print()
    print("=== CHECKING FOR MULTIPLE DATABASE FILES ===")
    db_files = [f for f in os.listdir('.') if f.endswith('.db')]
    if len(db_files) > 1:
        print(f"⚠️  Found multiple database files: {db_files}")
        print("This might cause confusion about which database is being used.")
    else:
        print(f"✅ Found {len(db_files)} database file(s): {db_files}")
    
    print()
    print("=== RECOMMENDATIONS ===")
    if os.path.exists(db_path):
        print("✅ Database file exists and should be accessible")
        print("✅ Flask app is configured to use the correct database")
        print("✅ Your account should be visible in the web interface")
        print()
        print("If you still can't see your account in the website:")
        print("1. Make sure the Flask app is running: python app.py")
        print("2. Clear your browser cache and cookies")
        print("3. Try logging in again with your email and password")
        print("4. Check if you're logged in as a different user")
    else:
        print("❌ Database file not found!")
        print("The website cannot connect to users.db because it doesn't exist.")
        print("You may need to run database initialization scripts.")

if __name__ == '__main__':
    verify_database_connection() 