#!/usr/bin/env python3
"""
Script to remove schedules that don't have names from the database.
This script will find and delete all work schedules where the name field is empty, NULL, or contains only whitespace.
"""

import sqlite3
import os
from datetime import datetime

def connect_to_database():
    """Connect to the SQLite database"""
    db_path = 'users.db'
    if not os.path.exists(db_path):
        print(f"Error: Database file '{db_path}' not found!")
        return None
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row  # This allows accessing columns by name
        return conn
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
        return None

def get_empty_schedules(conn):
    """Get all schedules that don't have names"""
    try:
        cursor = conn.cursor()
        
        # Find schedules where name is NULL, empty, or only whitespace
        query = """
        SELECT id, name, schedule_type, organization_id, created_by, created_at
        FROM work_schedule 
        WHERE name IS NULL 
           OR name = '' 
           OR trim(name) = ''
        ORDER BY id
        """
        
        cursor.execute(query)
        empty_schedules = cursor.fetchall()
        return empty_schedules
        
    except sqlite3.Error as e:
        print(f"Error querying database: {e}")
        return []

def display_empty_schedules(schedules):
    """Display the empty schedules that will be deleted"""
    if not schedules:
        print("No schedules with empty names found.")
        return
    
    print(f"\nFound {len(schedules)} schedule(s) with empty names:")
    print("-" * 80)
    print(f"{'ID':<5} {'Name':<20} {'Type':<10} {'Org ID':<8} {'Created By':<12} {'Created At':<20}")
    print("-" * 80)
    
    for schedule in schedules:
        name = schedule['name'] if schedule['name'] else '(NULL)'
        schedule_type = schedule['schedule_type'] if schedule['schedule_type'] else '(NULL)'
        org_id = schedule['organization_id'] if schedule['organization_id'] is not None else '(NULL)'
        created_by = schedule['created_by'] if schedule['created_by'] is not None else '(NULL)'
        created_at = schedule['created_at'] if schedule['created_at'] else '(NULL)'
        
        print(f"{schedule['id']:<5} {name:<20} {schedule_type:<10} {org_id:<8} {created_by:<12} {created_at:<20}")

def check_dependencies(conn, schedule_ids):
    """Check if any employees are assigned to these schedules"""
    if not schedule_ids:
        return {}
    
    try:
        cursor = conn.cursor()
        
        # Check for employees assigned to these schedules
        placeholders = ','.join(['?' for _ in schedule_ids])
        query = f"""
        SELECT schedule_id, COUNT(*) as employee_count
        FROM user 
        WHERE schedule_id IN ({placeholders})
        GROUP BY schedule_id
        """
        
        cursor.execute(query, schedule_ids)
        dependencies = {row['schedule_id']: row['employee_count'] for row in cursor.fetchall()}
        return dependencies
        
    except sqlite3.Error as e:
        print(f"Error checking dependencies: {e}")
        return {}

def remove_empty_schedules(conn, schedules, dependencies):
    """Remove the empty schedules from the database"""
    if not schedules:
        print("No schedules to remove.")
        return
    
    try:
        cursor = conn.cursor()
        
        # First, update any employees assigned to these schedules to remove the assignment
        schedule_ids = [schedule['id'] for schedule in schedules]
        placeholders = ','.join(['?' for _ in schedule_ids])
        
        # Update employees to remove schedule assignment
        update_query = f"""
        UPDATE user 
        SET schedule_id = NULL 
        WHERE schedule_id IN ({placeholders})
        """
        
        cursor.execute(update_query, schedule_ids)
        updated_employees = cursor.rowcount
        
        # Now delete the empty schedules
        delete_query = f"""
        DELETE FROM work_schedule 
        WHERE id IN ({placeholders})
        """
        
        cursor.execute(delete_query, schedule_ids)
        deleted_schedules = cursor.rowcount
        
        # Commit the changes
        conn.commit()
        
        print(f"\nOperation completed successfully!")
        print(f"- Updated {updated_employees} employee(s) to remove schedule assignments")
        print(f"- Deleted {deleted_schedules} schedule(s) with empty names")
        
        return deleted_schedules, updated_employees
        
    except sqlite3.Error as e:
        print(f"Error removing schedules: {e}")
        conn.rollback()
        return 0, 0

def main():
    """Main function to execute the schedule cleanup"""
    print("=" * 60)
    print("SCHEDULE CLEANUP TOOL")
    print("Removing schedules with empty names from database")
    print("=" * 60)
    
    # Connect to database
    conn = connect_to_database()
    if not conn:
        return
    
    try:
        # Get empty schedules
        empty_schedules = get_empty_schedules(conn)
        
        if not empty_schedules:
            print("No schedules with empty names found. Database is clean!")
            return
        
        # Display the schedules that will be removed
        display_empty_schedules(empty_schedules)
        
        # Check for dependencies
        schedule_ids = [schedule['id'] for schedule in empty_schedules]
        dependencies = check_dependencies(conn, schedule_ids)
        
        if dependencies:
            print(f"\n⚠️  WARNING: Found employees assigned to some of these schedules:")
            for schedule_id, count in dependencies.items():
                print(f"   - Schedule ID {schedule_id}: {count} employee(s) assigned")
            print("   These employees will have their schedule assignments removed.")
        
        # Ask for confirmation
        print(f"\nThis will permanently delete {len(empty_schedules)} schedule(s) from the database.")
        response = input("Do you want to proceed? (yes/no): ").strip().lower()
        
        if response not in ['yes', 'y']:
            print("Operation cancelled.")
            return
        
        # Perform the cleanup
        deleted_count, updated_count = remove_empty_schedules(conn, empty_schedules, dependencies)
        
        if deleted_count > 0:
            print(f"\n✅ Successfully cleaned up {deleted_count} empty schedule(s)!")
            if updated_count > 0:
                print(f"   - {updated_count} employee(s) had their schedule assignments cleared")
        else:
            print("\n❌ No schedules were deleted.")
            
    except Exception as e:
        print(f"An error occurred: {e}")
        
    finally:
        conn.close()
        print("\nDatabase connection closed.")

if __name__ == "__main__":
    main() 