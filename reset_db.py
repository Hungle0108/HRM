from app import app, db

def reset_database():
    with app.app_context():
        # Drop all tables first
        db.drop_all()
        # Create all tables fresh
        db.create_all()
        print("Database reset successfully!")

if __name__ == '__main__':
    reset_database() 