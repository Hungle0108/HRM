#!/usr/bin/env python3
"""
Test script to verify schedule relationship between employees and schedules
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, WorkSchedule

def test_schedule_relationship():
    """Test the schedule relationship between employees and schedules"""
    
    with app.app_context():
        try:
            # Get all users
            users = User.query.all()
            print(f"Found {len(users)} users in database")
            
            # Get all schedules
            schedules = WorkSchedule.query.all()
            print(f"Found {len(schedules)} schedules in database")
            
            # Check users with schedules
            users_with_schedules = User.query.filter(User.schedule_id.isnot(None)).all()
            print(f"Found {len(users_with_schedules)} users with assigned schedules")
            
            for user in users_with_schedules:
                print(f"User: {user.name} (ID: {user.id})")
                print(f"  Email: {user.email}")
                print(f"  Schedule ID: {user.schedule_id}")
                if user.schedule:
                    print(f"  Schedule Name: {user.schedule.name}")
                    print(f"  Schedule Type: {user.schedule.schedule_type}")
                else:
                    print(f"  Schedule: None (orphaned reference)")
                print()
            
            # Check users without schedules
            users_without_schedules = User.query.filter(User.schedule_id.is_(None)).all()
            print(f"Found {len(users_without_schedules)} users without assigned schedules")
            
            for user in users_without_schedules[:5]:  # Show first 5
                print(f"User: {user.name} (ID: {user.id}) - No schedule assigned")
            
            if len(users_without_schedules) > 5:
                print(f"... and {len(users_without_schedules) - 5} more users without schedules")
            
            print("\n" + "="*50)
            print("SCHEDULE RELATIONSHIP TEST COMPLETED")
            print("="*50)
            
        except Exception as e:
            print(f"Error testing schedule relationship: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test_schedule_relationship() 