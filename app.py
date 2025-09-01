from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import requests
import json
import os
from datetime import datetime
import bcrypt
from functools import wraps
import sqlite3
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')

# Database configuration
DATABASE = "mood_tracker.db"

# Hugging Face API configuration
HF_API_URL = "https://api-inference.huggingface.co/models/j-hartmann/emotion-english-distilroberta-base"
# Get the token from environment variable with a fallback
HF_API_TOKEN = os.getenv('HF_API_TOKEN')

if not HF_API_TOKEN:
    print("WARNING: HF_API_TOKEN environment variable is not set!")
    # In production, you might want to exit here or handle this differently

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
    """Call Hugging Face API for real emotion analysis"""
    if not HF_API_TOKEN:
        print("Hugging Face API token is not set!")
        return None

    headers = {
        "Authorization": f"Bearer {HF_API_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        # Create a session with retry logic
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.1, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('https://', adapter)

        response = session.post(
            HF_API_URL,
            headers=headers,
            json={"inputs": text},
            timeout=30
        )

        response.raise_for_status()  # will raise for 4xx or 5xx HTTP codes

        raw = response.json()

        # Some HF models return nested lists
        if isinstance(raw, list) and len(raw) > 0 and isinstance(raw[0], list):
            raw = raw[0]

        results = [{"label": item["label"], "score": float(item["score"])} for item in raw]
        return results

    except requests.exceptions.HTTPError as errh:
        print(f"Hugging Face HTTP error: {errh}")
        if response.status_code == 401:
            print("Invalid Hugging Face API token. Please check your HF_API_TOKEN environment variable.")
        return None
    except requests.exceptions.ConnectionError as errc:
        print(f"Connection error: {errc}")
        return None
    except requests.exceptions.Timeout as errt:
        print(f"Timeout error: {errt}")
        return None
    except Exception as e:
        print(f"Unexpected error calling Hugging Face API: {e}")
        return None

@app.route('/analyze_emotions', methods=['POST'])
@login_required
def analyze_emotions():
    data = request.get_json()
    text = data.get('text', '').strip()

    if not text:
        return jsonify({"success": False, "message": "Text cannot be empty"}), 400

    # Check if API token is available
    if not HF_API_TOKEN:
        return jsonify({
            "success": False, 
            "message": "Emotion analysis service is currently unavailable. Please try again later."
        }), 503

    # Call Hugging Face API
    results = analyze_emotion(text)

    if not results:
        # Fallback to simple emotion detection if API fails
        emotions = fallback_emotion_analysis(text)
        return jsonify({
            "success": True, 
            "results": emotions,
            "message": "Using fallback emotion analysis"
        })

    # Save to DB
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO journal_entries (user_id, journal_text, emotion_scores) VALUES (?, ?, ?)",
                (session['user_id'], text, json.dumps(results))
            )
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Database error: {e}")

    return jsonify({"success": True, "results": results})

def fallback_emotion_analysis(text):
    """Simple fallback emotion analysis when API is unavailable"""
    text = text.lower()
    emotions = {
        "anger": 0,
        "disgust": 0,
        "fear": 0,
        "joy": 0,
        "neutral": 0.5,  # Default to somewhat neutral
        "sadness": 0,
        "surprise": 0
    }
    
    # Simple keyword matching
    positive_words = ["happy", "joy", "excited", "good", "great", "wonderful", "love", "like"]
    negative_words = ["sad", "angry", "hate", "bad", "terrible", "awful", "disgust", "fear", "scared"]
    
    positive_count = sum(1 for word in positive_words if word in text)
    negative_count = sum(1 for word in negative_words if word in text)
    
    if positive_count > negative_count:
        emotions["joy"] = 0.7
        emotions["neutral"] = 0.3
    elif negative_count > positive_count:
        emotions["sadness"] = 0.5
        emotions["anger"] = 0.3
        emotions["neutral"] = 0.2
    
    # Convert to the same format as the API response
    return [{"label": k, "score": v} for k, v in emotions.items()]

# The rest of your routes remain the same...
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
@login_required
def feedback():
    if request.method == 'POST':
        data = request.get_json()
        message = data.get('message')

        if not message or not message.strip():
            return jsonify({"success": False, "message": "Message cannot be empty"})

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO feedback (user_id, message) VALUES (?, ?)", 
                          (session['user_id'], message))
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