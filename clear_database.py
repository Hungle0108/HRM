from app import db, User, app, Group

def clear_users():
    try:
        # Delete all users
        User.query.delete()
        db.session.commit()
        print("Successfully deleted all user records from the database.")
    except Exception as e:
        db.session.rollback()
        print(f"Error occurred while clearing database: {e}")

def create_group_admins_table():
    try:
        with app.app_context():
            db.engine.execute('''
                CREATE TABLE IF NOT EXISTS group_admins (
                    group_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    PRIMARY KEY (group_id, user_id),
                    FOREIGN KEY(group_id) REFERENCES "group" (id),
                    FOREIGN KEY(user_id) REFERENCES user (id)
                );
            ''')
        print("Successfully created group_admins association table.")
    except Exception as e:
        print(f"Error creating group_admins table: {e}")

def migrate_group_admins():
    with app.app_context():
        groups = db.session.execute('SELECT id, admin_user_id FROM "group" WHERE admin_user_id IS NOT NULL').fetchall()
        for group in groups:
            group_id = group[0]
            admin_user_id = group[1]
            # Insert into group_admins if not already present
            db.engine.execute('''
                INSERT OR IGNORE INTO group_admins (group_id, user_id) VALUES (?, ?)''', (group_id, admin_user_id))
        print(f"Migrated {len(groups)} group admins to group_admins table.")
        db.session.commit()

def drop_admin_user_id_column():
    """Drop the admin_user_id column from the group table since we now use many-to-many relationship"""
    with app.app_context():
        try:
            # SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
            # First, create a new table without admin_user_id
            db.engine.execute('''
                CREATE TABLE group_new (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(120) NOT NULL,
                    status VARCHAR(20),
                    organization_id INTEGER NOT NULL,
                    contracts_count INTEGER DEFAULT 0,
                    created_at DATETIME,
                    FOREIGN KEY(organization_id) REFERENCES organization (id)
                );
            ''')
            
            # Copy data from old table to new table (excluding admin_user_id)
            db.engine.execute('''
                INSERT INTO group_new (id, name, status, organization_id, contracts_count, created_at)
                SELECT id, name, status, organization_id, contracts_count, created_at FROM "group";
            ''')
            
            # Drop the old table and rename the new one
            db.engine.execute('DROP TABLE "group";')
            db.engine.execute('ALTER TABLE group_new RENAME TO "group";')
            
            db.session.commit()
            print("Successfully removed admin_user_id column from group table.")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error dropping admin_user_id column: {e}")

if __name__ == "__main__":
    migrate_group_admins()
    drop_admin_user_id_column() 