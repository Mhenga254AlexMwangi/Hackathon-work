from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import requests
import json
import os
from datetime import datetime
import bcrypt
from functools import wraps
import sqlite3

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Database configuration
DATABASE = "mood_tracker.db"

# Hugging Face API configuration
HF_API_URL = "https://api-inference.huggingface.co/models/j-hartmann/emotion-english-distilroberta-base"
HF_API_TOKEN = os.getenv('HF_API_TOKEN', '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')

def get_db_connection():
    try:
        connection = sqlite3.connect(DATABASE)
        connection.row_factory = sqlite3.Row  # return dict-like rows
        return connection
    except sqlite3.Error as err:
        print(f"Database connection error: {err}")
        return None

def init_db():
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS journal_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                journal_text TEXT,
                emotion_scores TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mood_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                mood_level INTEGER NOT NULL,
                journal_text TEXT,
                emotion_scores TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

        connection.commit()
        cursor.close()
        connection.close()
        print("SQLite database initialized successfully")

def login_required(f):
    """Decorator to ensure user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
def analyze_emotion(text):
    """Send text to Hugging Face API for emotion analysis"""
    if not HF_API_TOKEN or HF_API_TOKEN.startswith("hf_your_token"):
        print("⚠️ Hugging Face API token not configured, using mock data")
        return get_mock_emotion_data()
    
    headers = {
        "Authorization": f"Bearer {HF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            HF_API_URL, 
            headers=headers, 
            json={"inputs": text}, 
            timeout=30
        )
        if response.status_code == 200:
            raw = response.json()
            print("DEBUG HF response:", raw)

            # 🔹 Hugging Face often returns [[{label, score}, ...]]
            if isinstance(raw, list) and len(raw) > 0 and isinstance(raw[0], list):
                raw = raw[0]

            # 🔹 Ensure consistent format: [{label, score}, ...]
            return [
                {"label": item["label"], "score": float(item["score"])}
                for item in raw
            ]
        else:
            print(f"Hugging Face API error: {response.status_code} - {response.text}")
            return get_mock_emotion_data()
    except Exception as e:
        print(f"Error calling Hugging Face API: {e}")
        return get_mock_emotion_data()

@app.route('/analyze_emotions', methods=['POST'])
@login_required
def analyze_emotions():
    data = request.get_json()
    text = data.get('text', '')

    if not text.strip():
        return jsonify({"success": False, "message": "Text cannot be empty"}), 400

    # 🔹 Call Hugging Face API (normalized output)
    results = analyze_emotion(text)

    # Save to DB
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute(
                "INSERT INTO journal_entries (user_id, journal_text, emotion_scores) VALUES (?, ?, ?)",
                (session['user_id'], text, json.dumps(results))
            )
            connection.commit()
            cursor.close()
            connection.close()
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500

    return jsonify({"success": True, "results": results})


@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return render_template('login.html')

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required!'}), 400

    connection = get_db_connection()
    if not connection:
        return jsonify({'success': False, 'message': 'Database connection failed!'}), 500

    try:
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            session['user_name'] = user['name']
            return jsonify({'success': True, 'message': 'Login successful!'}), 200
        else:
            return jsonify({'success': False, 'message': 'Invalid email or password!'}), 401
    finally:
        connection.close()

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return render_template('signup.html')

    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required!'}), 400

    connection = get_db_connection()
    if not connection:
        return jsonify({'success': False, 'message': 'Database connection failed!'}), 500

    try:
        cursor = connection.cursor()
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'User already exists!'}), 409

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
                       (name, email, hashed_password.decode('utf-8')))
        connection.commit()
        session['user_id'] = cursor.lastrowid
        session['user_email'] = email
        session['user_name'] = name
        return jsonify({'success': True, 'message': 'Signup successful!'}), 201
    finally:
        connection.close()

@app.route('/dashboard')
@login_required
def dashboard():
    connection = get_db_connection()
    mood_data = [0, 0, 0, 0, 0]
    recent_feedback = []
    trend_data = []

    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute('SELECT mood_level, COUNT(*) FROM mood_entries WHERE user_id = ? GROUP BY mood_level',
                           (session['user_id'],))
            mood_results = cursor.fetchall()
            for mood_level, count in mood_results:
                mood_data[mood_level - 1] = count

            cursor.execute('SELECT message, created_at FROM feedback WHERE user_id = ? ORDER BY created_at DESC LIMIT 5',
                           (session['user_id'],))
            recent_feedback = cursor.fetchall()

            cursor.execute('''
                SELECT DATE(created_at), AVG(mood_level) 
                FROM mood_entries 
                WHERE user_id = ? AND created_at >= DATE('now','-7 day')
                GROUP BY DATE(created_at)
                ORDER BY DATE(created_at)
            ''', (session['user_id'],))
            trend_results = cursor.fetchall()
            for date, avg_mood in trend_results:
                trend_data.append({'date': date, 'avg_mood': float(avg_mood)})
        finally:
            connection.close()

    return render_template('dashboard.html', mood_data=mood_data,
                           recent_feedback=recent_feedback,
                           trend_data=trend_data,
                           user_name=session.get('user_name', 'User'))
@app.route('/journal')
@login_required
def journal():
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT * FROM journal_entries WHERE user_id = ? ORDER BY created_at DESC",
            (session['user_id'],)
        )
        entries = cursor.fetchall()
        cursor.close()
        connection.close()
    else:
        entries = []

    return render_template("journal.html", entries=entries)
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        data = request.get_json()
        message = data.get('message')

        if not message.strip():
            return jsonify({"success": False, "message": "Message cannot be empty"})

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO feedback (message) VALUES (?)", (message,))
            conn.commit()
            conn.close()

            return jsonify({"success": True, "message": "Feedback submitted successfully"})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})
    
    return render_template("feedback.html")
@app.route('/tips')
def tips():
    return render_template("tips.html")
@app.route('/logout')
def logout():
    # Clear all session data
    session.clear()
    # Redirect to login page
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5002)

