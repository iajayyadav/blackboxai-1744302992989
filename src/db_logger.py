import sqlite3
from datetime import datetime
import os

class HistoryLogger:
    """Handles logging of file operations in SQLite database."""
    
    def __init__(self, db_path="data/history.db"):
        """Initialize the database connection and create tables if they don't exist."""
        # Ensure the data directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize the database with required tables."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create operations table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS operations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_path TEXT NOT NULL,
                        operation TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        status TEXT NOT NULL,
                        error_details TEXT
                    )
                ''')
                
                conn.commit()
                
        except sqlite3.Error as e:
            raise Exception(f"Database initialization failed: {str(e)}")

    def log_operation(self, file_path: str, operation: str, status: str, error_details: str = None):
        """Log a file operation to the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO operations (file_path, operation, timestamp, status, error_details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (file_path, operation, datetime.now(), status, error_details))
                
                conn.commit()
                
        except sqlite3.Error as e:
            raise Exception(f"Failed to log operation: {str(e)}")

    def get_history(self, limit: int = None):
        """Retrieve operation history from the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = '''
                    SELECT id, file_path, operation, timestamp, status, error_details
                    FROM operations
                    ORDER BY timestamp DESC
                '''
                
                if limit:
                    query += f' LIMIT {limit}'
                
                cursor.execute(query)
                columns = [description[0] for description in cursor.description]
                rows = cursor.fetchall()
                
                # Convert to list of dictionaries for easier handling
                history = []
                for row in rows:
                    history.append(dict(zip(columns, row)))
                
                return history
                
        except sqlite3.Error as e:
            raise Exception(f"Failed to retrieve history: {str(e)}")

    def clear_history(self):
        """Clear all operation history from the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM operations')
                conn.commit()
                
        except sqlite3.Error as e:
            raise Exception(f"Failed to clear history: {str(e)}")
