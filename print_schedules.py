import sqlite3
import json

import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'users.db')

def print_default_templates():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, schedule_data FROM work_schedule WHERE organization_id=0 AND is_default=1")
    rows = cursor.fetchall()
    for row in rows:
        print(f"ID: {row[0]}, Name: {row[1]}\nData: {row[2]}\n")
        try:
            data = json.loads(row[2])
            print(json.dumps(data, indent=2))
        except Exception as e:
            print(f"Error parsing JSON: {e}")
    conn.close()

if __name__ == '__main__':
    print_default_templates() 