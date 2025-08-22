
from flask import Flask, request, session

app = Flask(__name__)

# VULNERABLE: Admin endpoint without authentication
@app.route('/admin')
def admin_panel():
    return "Admin Panel - Sensitive Data"

# VULNERABLE: User data endpoint without proper auth
@app.route('/user/data')
def get_user_data():
    user_id = request.args.get('user_id')
    # Should check if current user can access this data
    return f"User data for {user_id}"
