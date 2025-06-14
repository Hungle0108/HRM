from app import db, User

def clear_users():
    try:
        # Delete all users
        User.query.delete()
        db.session.commit()
        print("Successfully deleted all user records from the database.")
    except Exception as e:
        db.session.rollback()
        print(f"Error occurred while clearing database: {e}")

if __name__ == "__main__":
    clear_users() 