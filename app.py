import os
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, request, jsonify
from flask_cors import CORS
from evaluator import run_full_evaluation
from supabase import create_client, Client
import bcrypt
import jwt
import datetime
from middleware import get_owner_id_from_jwt

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
JWT_SECRET = os.environ.get("JWT_SECRET")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)
CORS(app) 

@app.route('/signup', methods=['POST'])
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
    try:
        existing = supabase.table('authentication').select('id').eq('email', email).execute()
        if existing.data:
            return jsonify({'error': 'Email already registered'}), 409
        result = supabase.table('authentication').insert(user_data).execute()
        if not result.data:
            return jsonify({'error': 'Signup failed'}), 500
        user_id = result.data[0]['id']
    except Exception:
        return jsonify({'error': 'Signup failed'}), 500

    token = jwt.encode({
        'id': user_id,
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }, JWT_SECRET, algorithm='HS256')
    return jsonify({'token': token, 'id': user_id})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not all([email, password]):
        return jsonify({'error': 'Missing email or password'}), 400
    try:
        user = supabase.table('authentication').select('*').eq('email', email).single().execute()
        user_data = user.data
    except Exception:
        return jsonify({'error': 'Invalid credentials'}), 401
    if not bcrypt.checkpw(password.encode('utf-8'), user_data['password_hash'].encode('utf-8')):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = jwt.encode({
        'id': user_data['id'],
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }, JWT_SECRET, algorithm='HS256')
    return jsonify({'token': token, 'id': user_data['id']})

@app.route('/evaluate', methods=['POST'])
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

@app.route('/jobs', methods=['POST'])
def create_job():
    owner_id, error_response, status_code = get_owner_id_from_jwt()
    if error_response:
        return error_response, status_code
    data = request.get_json()
    job_id = data.get('id')
    title = data.get('title')
    description = data.get('description')
    skill_condition = data.get('skill_condition')

    if not all([job_id, title, description]):
        return jsonify({'error': 'Missing required fields'}), 400

    job_data = {
        'id': job_id,
        'title': title,
        'description': description,
        'skill_condition': skill_condition,
        'owner_id': owner_id
    }
    try:
        result = supabase.table('jobs').insert(job_data).execute()
        if not result.data:
            return jsonify({'error': 'Job creation failed'}), 500
        return jsonify({'job': result.data[0]}), 201
    except Exception:
        return jsonify({'error': 'Job creation failed'}), 500

@app.route('/')
def root():
    return jsonify({'status': 'ok', 'message': 'AI Recruitment API is running.'})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)