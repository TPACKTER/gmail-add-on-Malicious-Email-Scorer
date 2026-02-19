import sqlite3

DB_NAME = "scanner.db"

def init_db():
    """Initializes the SQLite database with the required tables."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Table to track previous scans [cite: 21]
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            subject TEXT,
            score INTEGER,
            verdict TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Table to allow users to define personal blacklist entries 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            email TEXT PRIMARY KEY
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Returns an active database connection."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row # Allows us to access columns by name
    return conn