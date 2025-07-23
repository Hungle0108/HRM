import sqlite3
import json
from datetime import datetime

DB_PATH = 'users.db'

def insert_default_templates():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Remove previous default templates to avoid duplicates and errors
    cursor.execute("DELETE FROM work_schedule WHERE organization_id=0 AND is_default=1")
    conn.commit()

    # Example default templates
    templates = [
        {
            'name': 'Standard Office Hours',
            'schedule_type': 'fixed',
            'schedule_data': json.dumps({
                'scheduleDetails': {
                    'shifts': {
                        '1': {
                            'includeTime': True,
                            'weekdays': {
                                'monday': {'checked': True, 'startTime': '08:00', 'endTime': '17:00'},
                                'tuesday': {'checked': True, 'startTime': '08:00', 'endTime': '17:00'},
                                'wednesday': {'checked': True, 'startTime': '08:00', 'endTime': '17:00'},
                                'thursday': {'checked': True, 'startTime': '08:00', 'endTime': '17:00'},
                                'friday': {'checked': True, 'startTime': '08:00', 'endTime': '17:00'},
                                'saturday': {'checked': False},
                                'sunday': {'checked': False}
                            }
                        }
                    }
                }
            })
        },
        {
            'name': '2-Shift Work',
            'schedule_type': 'fixed',
            'schedule_data': json.dumps({
                'scheduleDetails': {
                    'shifts': {
                        '1': {
                            'includeTime': True,
                            'weekdays': {
                                'monday': {'checked': True, 'startTime': '06:00', 'endTime': '14:00'},
                                'tuesday': {'checked': True, 'startTime': '06:00', 'endTime': '14:00'},
                                'wednesday': {'checked': True, 'startTime': '06:00', 'endTime': '14:00'},
                                'thursday': {'checked': True, 'startTime': '06:00', 'endTime': '14:00'},
                                'friday': {'checked': True, 'startTime': '06:00', 'endTime': '14:00'},
                                'saturday': {'checked': True, 'startTime': '06:00', 'endTime': '14:00'},
                                'sunday': {'checked': False}
                            }
                        },
                        '2': {
                            'includeTime': True,
                            'weekdays': {
                                'monday': {'checked': True, 'startTime': '14:00', 'endTime': '22:00'},
                                'tuesday': {'checked': True, 'startTime': '14:00', 'endTime': '22:00'},
                                'wednesday': {'checked': True, 'startTime': '14:00', 'endTime': '22:00'},
                                'thursday': {'checked': True, 'startTime': '14:00', 'endTime': '22:00'},
                                'friday': {'checked': True, 'startTime': '14:00', 'endTime': '22:00'},
                                'saturday': {'checked': True, 'startTime': '14:00', 'endTime': '22:00'},
                                'sunday': {'checked': False}
                            }
                        }
                    }
                }
            })
        },
        {
            'name': 'Extended Hours',
            'schedule_type': 'fixed',
            'schedule_data': json.dumps({
                'scheduleDetails': {
                    'shifts': {
                        '1': {
                            'includeTime': True,
                            'weekdays': {
                                'monday': {'checked': True, 'startTime': '07:00', 'endTime': '19:00'},
                                'tuesday': {'checked': True, 'startTime': '07:00', 'endTime': '19:00'},
                                'wednesday': {'checked': True, 'startTime': '07:00', 'endTime': '19:00'},
                                'thursday': {'checked': True, 'startTime': '07:00', 'endTime': '19:00'},
                                'friday': {'checked': True, 'startTime': '07:00', 'endTime': '19:00'},
                                'saturday': {'checked': False},
                                'sunday': {'checked': False}
                            }
                        }
                    }
                }
            })
        }
    ]

    for template in templates:
        cursor.execute(
            """
            INSERT INTO work_schedule (name, schedule_type, organization_id, created_by, created_at, is_default, schedule_data)
            VALUES (?, ?, 0, 0, ?, 1, ?)
            """,
            (template['name'], template['schedule_type'], None, template['schedule_data'])
        )
        print(f"Inserted template: {template['name']}")
    conn.commit()
    conn.close()

if __name__ == '__main__':
    insert_default_templates() 