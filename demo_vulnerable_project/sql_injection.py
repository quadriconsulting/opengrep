
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # VULNERABLE: SQL injection via f-string
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    return cursor.fetchone()

def search_users(search_term):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # VULNERABLE: SQL injection via string concatenation
    cursor.execute("SELECT * FROM users WHERE name LIKE '%" + search_term + "%'")
    
    return cursor.fetchall()
