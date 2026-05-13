import pickle
import sqlite3
import os
import tempfile

def load_session(data):
    # Dangerous: Pickle Deserialization
    return pickle.loads(data)

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Dangerous: SQL Injection
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchone()

def save_log(msg):
    # Dangerous: Predictable Temp File
    path = os.path.join(tempfile.gettempdir(), "app_log.txt")
    with open(path, "a") as f:
        f.write(msg)
