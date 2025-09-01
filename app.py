from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import mysql.connector
import requests
import json
import os
from datetime import datetime
import bcrypt
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'new_password',
    'database': 'mood_tracker'
}

# Hugging Face API configuration
HF_API_URL = "https://api-inference.huggingface.co/models/j-hartmann/emotion-english-distilroberta-base"
HF_API_TOKEN = os.getenv('HF_API_TOKEN', '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')

def get_db_connection():
    try:
        connection = mysql.connector.connect(**db_config)
        return connection
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

def init_db():
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create journal_entries table with user relationship
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS journal_entries (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                journal_text TEXT,
                emotion_scores JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Create mood_entries table with user relationship
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mood_entries (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                mood_level INT NOT NULL,
                journal_text TEXT,
                emotion_scores JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Create feedback table with user relationship
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Add user_id column to existing tables if they don't have it
        try:
            cursor.execute("ALTER TABLE journal_entries ADD COLUMN user_id INT")
            cursor.execute("ALTER TABLE mood_entries ADD COLUMN user_id INT")
            cursor.execute("ALTER TABLE feedback ADD COLUMN user_id INT")
        except mysql.connector.Error as err:
            # Columns might already exist, which is fine
            if not err.errno == 1060:  # Duplicate column name error
                print(f"Error adding user_id columns: {err}")
        
        connection.commit()
        cursor.close()
        connection.close()
        print("Database initialized successfully")
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
    # Check if token is properly configured
    if not HF_API_TOKEN or HF_API_TOKEN == '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':
        print("Hugging Face API token not configured, using mock data")
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
        
        # Handle different response scenarios
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            print(f"Hugging Face API authentication failed: {response.text}")
            print("Please check your API token validity and permissions")
            return get_mock_emotion_data()
        elif response.status_code == 503:
            print("Model is loading, please try again shortly")
            return get_mock_emotion_data()
        else:
            print(f"Hugging Face API error: {response.status_code} - {response.text}")
            return get_mock_emotion_data()
            
    except requests.exceptions.Timeout:
        print("Hugging Face API request timed out")
        return get_mock_emotion_data()
    except Exception as e:
        print(f"Error calling Hugging Face API: {e}")
        return get_mock_emotion_data()
    
@app.route('/check-token')
def check_token():
    """Test endpoint to verify Hugging Face token configuration"""
    token_status = {
        "token_configured": bool(HF_API_TOKEN and HF_API_TOKEN != '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'),
        "token_length": len(HF_API_TOKEN) if HF_API_TOKEN else 0,
        "token_prefix": HF_API_TOKEN[:4] if HF_API_TOKEN and len(HF_API_TOKEN) > 4 else "None"
    }
    
    # Test the token with a simple API call
    if token_status["token_configured"]:
        headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
        test_response = requests.get("https://huggingface.co/api/whoami-v2", headers=headers)
        token_status["api_response"] = test_response.status_code
        token_status["api_message"] = test_response.text[:100] + "..." if test_response.text else "No response"
    
    return jsonify(token_status)

def get_mock_emotion_data():
    """Return realistic mock emotion data"""
    return [
        {"label": "joy", "score": 0.65},
        {"label": "sadness", "score": 0.20},
        {"label": "anger", "score": 0.07},
        {"label": "fear", "score": 0.05},
        {"label": "surprise", "score": 0.02},
        {"label": "disgust", "score": 0.01}
    ]

# Define all the routes
@app.route('/')
def home():
    """Redirect to login page"""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'GET':
        # If user is already logged in, redirect to dashboard
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return render_template('login.html')
    

    # Handle POST request
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required!'}), 400
    
    connection = get_db_connection()
    if not connection:
        return jsonify({'success': False, 'message': 'Database connection failed!'}), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            # Store user info in session
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            session['user_name'] = user['name']
            
            return jsonify({
                'success': True, 
                'message': 'Login successful!',
                'user': {
                    'id': user['id'],
                    'name': user['name'],
                    'email': user['email']
                }
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Invalid email or password!'}), 401
            
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'success': False, 'message': 'Database error!'}), 500
    finally:
        if connection:
            connection.close()

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Signup page"""
    if request.method == 'GET':
        # If user is already logged in, redirect to dashboard
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return render_template('signup.html')
    
    # Handle POST request
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    
    if not name or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required!'}), 400
    
    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters long!'}), 400
    
    connection = get_db_connection()
    if not connection:
        return jsonify({'success': False, 'message': 'Database connection failed!'}), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Check if user already exists
        cursor.execute('SELECT id FROM users WHERE email = %s', (email,))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'User already exists with this email!'}), 409
        
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Create new user
        cursor.execute(
            'INSERT INTO users (name, email, password) VALUES (%s, %s, %s)',
            (name, email, hashed_password.decode('utf-8'))
        )
        connection.commit()
        
        # Get the new user ID
        user_id = cursor.lastrowid
        
        # Store user info in session
        session['user_id'] = user_id
        session['user_email'] = email
        session['user_name'] = name
        
        return jsonify({
            'success': True,
            'message': 'User created successfully!',
            'user': {
                'id': user_id,
                'name': name,
                'email': email
            }
        }), 201
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'success': False, 'message': 'Database error!'}), 500
    finally:
        if connection:
            connection.close()

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/checkin', methods=['GET', 'POST'])
@login_required
def checkin():
    if request.method == 'POST':
        try:
            data = request.get_json()
            mood_level = data.get('mood')
            journal_text = data.get('journal')
            
            # Analyze emotion using Hugging Face API
            emotion_scores = None
            if journal_text:
                emotion_result = analyze_emotion(journal_text)
                if emotion_result:
                    emotion_scores = json.dumps(emotion_result)
            
            # Save to database
            connection = get_db_connection()
            if connection:
                cursor = connection.cursor()
                cursor.execute(
                    'INSERT INTO mood_entries (user_id, mood_level, journal_text, emotion_scores) VALUES (%s, %s, %s, %s)',
                    (session['user_id'], mood_level, journal_text, emotion_scores)
                )
                connection.commit()
                cursor.close()
                connection.close()
                
                return jsonify({'success': True, 'message': 'Mood entry saved successfully'})
            else:
                return jsonify({'success': False, 'message': 'Database connection failed'})
                
        except Exception as e:
            print(f"Error in checkin: {e}")
            return jsonify({'success': False, 'message': str(e)})
    
    return render_template('checkin.html')

@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    if request.method == 'POST':
        try:
            data = request.get_json()
            message = data.get('message')
            
            # Save to database
            connection = get_db_connection()
            if connection:
                cursor = connection.cursor()
                cursor.execute(
                    'INSERT INTO feedback (user_id, message) VALUES (%s, %s)',
                    (session['user_id'], message)
                )
                connection.commit()
                cursor.close()
                connection.close()
                
                return jsonify({'success': True, 'message': 'Feedback submitted successfully'})
            else:
                return jsonify({'success': False, 'message': 'Database connection failed'})
                
        except Exception as e:
            print(f"Error in feedback: {e}")
            return jsonify({'success': False, 'message': str(e)})
    
    return render_template('feedback.html')
@app.route('/dashboard')
def dashboard():
    # Require login
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('login'))

    connection = get_db_connection()
    mood_data = [0, 0, 0, 0, 0]  # Default empty data for moods 1-5
    recent_feedback = []
    trend_data = []
    
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Get mood distribution data for current user
            cursor.execute(
                'SELECT mood_level, COUNT(*) as count '
                'FROM mood_entries WHERE user_id = %s '
                'GROUP BY mood_level ORDER BY mood_level',
                (session['user_id'],)
            )
            mood_results = cursor.fetchall()
            
            # Format mood data for chart
            for result in mood_results:
                mood_index = int(result['mood_level']) - 1
                if 0 <= mood_index < 5:
                    mood_data[mood_index] = result['count']
            
            # Get recent feedback for current user
            cursor.execute(
                'SELECT message, created_at FROM feedback '
                'WHERE user_id = %s ORDER BY created_at DESC LIMIT 5',
                (session['user_id'],)
            )
            recent_feedback = cursor.fetchall()
            
            # Get mood trend data (last 7 days)
            cursor.execute(
                '''
                SELECT DATE(created_at) as date, AVG(mood_level) as avg_mood 
                FROM mood_entries 
                WHERE user_id = %s AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY DATE(created_at) 
                ORDER BY date
                ''',
                (session['user_id'],)
            )
            trend_results = cursor.fetchall()
            
            for result in trend_results:
                trend_data.append({
                    'date': result['date'].strftime('%Y-%m-%d'),
                    'avg_mood': float(result['avg_mood']) if result['avg_mood'] else 0
                })
            
            cursor.close()
        except mysql.connector.Error as err:
            print(f"Database error in dashboard: {err}")
        finally:
            connection.close()
    
    return render_template(
        'dashboard.html', 
        mood_data=mood_data, 
        recent_feedback=recent_feedback,
        trend_data=trend_data,
        user_name=session.get('user_name', 'User')
    )

@app.route('/tips')
@login_required
def tips():
    return render_template('tips.html')

@app.route('/journal')
@login_required
def journal():
    return render_template('journal.html')

@app.route('/analyze-emotions', methods=['POST'])
@login_required
def analyze_emotions():
    try:
        data = request.get_json()
        journal_text = data.get('journalText', '')
        
        if not journal_text:
            return jsonify({'error': 'No journal text provided'}), 400
        
        # Analyze emotion using Hugging Face API
        emotion_result = analyze_emotion(journal_text)

        # Normalize Hugging Face response
        if isinstance(emotion_result, list) and len(emotion_result) > 0 and isinstance(emotion_result[0], list):
            emotion_result = emotion_result[0]  # unwrap nested list
        
        # Format response
        emotions = []
        for item in emotion_result:
            emotions.append({
                'label': item['label'],
                'score': item['score']
            })
        
        return jsonify(emotions)
        
    except Exception as e:
        print(f"Error in analyze_emotions: {e}")
        # Return mock data as fallback
        mock_data = [
            {"label": "joy", "score": 0.65},
            {"label": "sadness", "score": 0.20},
            {"label": "anger", "score": 0.07},
            {"label": "fear", "score": 0.05},
            {"label": "surprise", "score": 0.02},
            {"label": "disgust", "score": 0.01}
        ]
        return jsonify(mock_data)

@app.route('/save-entry', methods=['POST'])
@login_required
def save_entry():
    try:
        data = request.get_json()
        journal_text = data.get('journalText', '')
        
        if not journal_text:
            return jsonify({'error': 'No journal text provided'}), 400
        
        # Analyze emotion
        emotion_result = analyze_emotion(journal_text)
        emotion_scores = json.dumps(emotion_result)
        
        # Save to database
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            cursor.execute(
                'INSERT INTO journal_entries (user_id, journal_text, emotion_scores) VALUES (%s, %s, %s)',
                (session['user_id'], journal_text, emotion_scores)
            )
            connection.commit()
            cursor.close()
            connection.close()
            
            return jsonify({'success': True, 'message': 'Journal entry saved successfully'})
        else:
            return jsonify({'success': False, 'message': 'Database connection failed'})
            
    except Exception as e:
        print(f"Error in save_entry: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5001)