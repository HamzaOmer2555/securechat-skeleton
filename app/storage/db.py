import os
import mysql.connector
import hashlib
from dotenv import load_dotenv

load_dotenv()

# DB Config
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_USER = os.getenv("DB_USER", "scuser")
DB_PASS = os.getenv("DB_PASSWORD", "scpass")
DB_NAME = os.getenv("DB_NAME", "securechat")

def get_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )

def init_db():
    """Creates the users table if not exists."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255),
            username VARCHAR(255) UNIQUE,
            salt VARBINARY(16),
            pwd_hash CHAR(64)
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()
    print("[*] Database initialized.")

def hash_password(salt: bytes, password: str) -> str:
    """Computes SHA256(salt || password) and returns hex string."""
    # PDF Requirement: pwd hash hex (SHA256 (salt || password)) 
    return hashlib.sha256(salt + password.encode('utf-8')).hexdigest()

def add_user(email, username, salt_b64, pwd_hash_hex):
    conn = get_connection()
    cursor = conn.cursor()
    import base64
    salt_bytes = base64.b64decode(salt_b64)
    try:
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt_bytes, pwd_hash_hex)
        )
        conn.commit()
        return True
    except mysql.connector.IntegrityError:
        return False
    finally:
        cursor.close()
        conn.close()

def get_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT email, username, salt, pwd_hash FROM users WHERE username = %s", (username,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row # (email, username, salt_bytes, pwd_hash)

if __name__ == "__main__":
    import sys
    if "--init" in sys.argv:
        init_db()