#!/usr/bin/env python3
"""
Migration script to add schedule_id column to User table
"""

import sqlite3
import os

def add_schedule_id_column():
    """Add schedule_id column to User table"""
    
    # Database file path
    db_path = 'users.db'
    
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found!")
        return
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if column already exists
        cursor.execute("PRAGMA table_info(user)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'schedule_id' in columns:
            print("schedule_id column already exists in User table")
            return
        
        # Add schedule_id column
        print("Adding schedule_id column to User table...")
        cursor.execute("ALTER TABLE user ADD COLUMN schedule_id INTEGER REFERENCES work_schedule(id)")
        
        # Commit changes
        conn.commit()
        print("Successfully added schedule_id column to User table")
        
        # Verify the column was added
        cursor.execute("PRAGMA table_info(user)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'schedule_id' in columns:
            print("✓ schedule_id column verified in User table")
        else:
            print("✗ schedule_id column not found in User table")
            
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    add_schedule_id_column() 