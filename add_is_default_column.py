import sqlite3

DB_PATH = 'users.db'  # Updated path to your SQLite database

def add_is_default_column():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Check if column already exists
    cursor.execute("PRAGMA table_info(work_schedule)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'is_default' not in columns:
        print('Adding is_default column to work_schedule...')
        cursor.execute("ALTER TABLE work_schedule ADD COLUMN is_default BOOLEAN DEFAULT 0")
        conn.commit()
        print('Column added.')
    else:
        print('is_default column already exists.')
    conn.close()

if __name__ == '__main__':
    add_is_default_column() 