import sqlite3 as sql
import os

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, 'threat_log.db')
SCHEMA_PATH = os.path.join(DB_DIR, 'schema.sql')

def init_db():
    # FIXED: Changed DB_DIR to DB_PATH
    conn = sql.connect(DB_PATH)
    cursor = conn.cursor()

    # FIXED: Opens SCHEMA_PATH perfectly now
    with open(SCHEMA_PATH, 'r') as f:
        sql_script = f.read()

    cursor.executescript(sql_script)
    conn.commit()
    conn.close()
    print(f"Database initialized at: {DB_PATH}")




if __name__ == "__main__":
    init_db()
