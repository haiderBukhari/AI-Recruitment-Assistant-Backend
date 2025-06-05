import os
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, request, jsonify
from evaluator import run_full_evaluation
from supabase import create_client, Client
import bcrypt
import jwt
import datetime

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
JWT_SECRET = os.environ.get("JWT_SECRET")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app_flask = Flask(__name__)

@app_flask.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    full_name = data.get('full_name')
    email = data.get('email')
    company_name = data.get('company_name')
    company_details = data.get('company_details')
    company_culture = data.get('company_culture')
    password = data.get('password')

    if not all([full_name, email, company_name, password]):
        return jsonify({'error': 'Missing required fields'}), 400

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    user_data = {
        'full_name': full_name,
        'email': email,
        'company_name': company_name,
        'company_details': company_details,
        'company_culture': company_culture,
        'password_hash': password_hash
    }
    # Check if user exists
    existing = supabase.table('authentication').select('id').eq('email', email).execute()
    if existing.data:
        return jsonify({'error': 'Email already registered'}), 409
    result = supabase.table('authentication').insert(user_data).execute()
    if not result.data:
        return jsonify({'error': 'Signup failed'}), 500
    user_id = result.data[0]['id']

    token = jwt.encode({
        'id': user_id,
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }, JWT_SECRET, algorithm='HS256')
    return jsonify({'token': token, 'id': user_id})

@app_flask.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not all([email, password]):
        return jsonify({'error': 'Missing email or password'}), 400
    user = supabase.table('authentication').select('*').eq('email', email).single().execute()
    if not user.data:
        return jsonify({'error': 'Invalid credentials'}), 401
    user_data = user.data
    if not bcrypt.checkpw(password.encode('utf-8'), user_data['password_hash'].encode('utf-8')):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = jwt.encode({
        'id': user_data['id'],
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }, JWT_SECRET, algorithm='HS256')
    return jsonify({'token': token, 'id': user_data['id']})

@app_flask.route('/evaluate', methods=['POST'])
def evaluate():
    data = request.get_json()
    job_title = data.get('job_title', '')
    job_description = data.get('job_description', '')
    skill_condition = data.get('skill_condition', '')
    company_info = data.get('company_info', '')
    cv = data.get('cv', '')
    cover_letter = data.get('cover_letter', '')
    result = run_full_evaluation(job_title, job_description, skill_condition, company_info, cv, cover_letter)
    return jsonify(result)

if __name__ == "__main__":
    app_flask.run(host='0.0.0.0', port=5000)