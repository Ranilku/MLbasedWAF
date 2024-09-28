from flask import Flask, request, render_template, redirect, url_for, flash, jsonify
import sqlite3
import logging
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Set up logging
logging.basicConfig(filename='webapp.log', level=logging.INFO)

# Connect to SQLite Database
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Log requests
def log_request(data):
    logging.info(f"Time: {datetime.now()}, Data: {data}")

# Homepage Route
@app.route('/')
def index():
    return render_template('index.html')

# Login Route (Simulate SQL Injection)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        conn.close()

        if user:
            flash('Login successful!', 'success')
            log_request(f"User {username} logged in successfully")
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Invalid credentials.', 'danger')
            log_request(f"Failed login attempt with username: {username}")
            return redirect(url_for('login'))
    return render_template('login.html')

# Dashboard Route (after login)
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# Search Route (Simulate XSS)
@app.route('/search', methods=['POST', 'GET'])
def search():
    if request.method == 'POST':
        query = request.form['query']
    else:
        query = request.args.get('query')

    conn = get_db_connection()
    results = conn.execute('SELECT * FROM search_history WHERE query LIKE ?', ('%' + query + '%',)).fetchall()
    conn.close()
    log_request(f"Search performed for query: {query}")
    return render_template('results.html', results=results)

# Local File Inclusion Route
@app.route('/view', methods=['GET'])
def view():
    page = request.args.get('page')
    log_request(f"Page view attempt: {page}")
    return f"Viewing page: {page}"

# Command Injection Route
@app.route('/command', methods=['GET'])
def command():
    cmd = request.args.get('cmd')
    if cmd:
        # Simulate executing the command (unsafe for demonstration)
        output = os.popen(cmd).read()
        log_request(f"Command executed: {cmd}")
        return jsonify({"command": cmd, "output": output})
    else:
        return jsonify({"error": "No command provided"}), 400

# Default 404 Route for undefined paths
@app.errorhandler(404)
def page_not_found(e):
    log_request(f"Attempted access to non-existent path: {request.path}")
    return "Path or route does not exist", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
