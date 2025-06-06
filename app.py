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
    title = data.get('title')
    description = data.get('description')
    skill_condition = data.get('skill_condition')

    if not all([title, description]):
        return jsonify({'error': 'Missing required fields'}), 400

    if skill_condition is not None:
        skill_condition_str = str(skill_condition)
    else:
        skill_condition_str = None

    job_data = {
        'title': title,
        'description': description,
        'skill_condition': skill_condition_str,
        'owner_id': owner_id
    }
    try:
        result = supabase.table('jobs').insert(job_data).execute()
        if not result.data:
            return jsonify({'error': 'Job creation failed'}), 500
        return jsonify({'job': result.data[0]}), 201
    except Exception:
        return jsonify({'error': 'Job creation failed'}), 500

@app.route('/company-info', methods=['GET'])
def get_company_info():
    owner_id, error_response, status_code = get_owner_id_from_jwt()
    if error_response:
        return error_response, status_code
    try:
        user = supabase.table('authentication').select('company_details', 'company_culture').eq('id', owner_id).single().execute()
        if not user.data:
            return jsonify({'error': 'Company info not found'}), 404
        return jsonify({
            'company_details': user.data.get('company_details'),
            'company_culture': user.data.get('company_culture')
        })
    except Exception:
        return jsonify({'error': 'Failed to fetch company info'}), 500

@app.route('/jobs', methods=['GET'])
def get_all_jobs():
    owner_id, error_response, status_code = get_owner_id_from_jwt()
    if error_response:
        return error_response, status_code
    try:
        result = supabase.table('jobs').select('*').eq('owner_id', owner_id).execute()
        return jsonify({'jobs': result.data}), 200
    except Exception:
        return jsonify({'error': 'Failed to fetch jobs'}), 500

@app.route('/jobs/<job_id>/toggle-status', methods=['PUT'])
def toggle_job_status(job_id):
    try:
        job = supabase.table('jobs').select('status').eq('id', job_id).single().execute()
        if not job.data or 'status' not in job.data:
            return jsonify({'error': 'Job not found'}), 404
        current_status = job.data['status']
        new_status = 'inactive' if current_status == 'active' else 'active'
        # Update status
        updated = supabase.table('jobs').update({'status': new_status}).eq('id', job_id).execute()
        if not updated.data:
            return jsonify({'error': 'Failed to update job status'}), 500
        return jsonify({'id': job_id, 'status': new_status}), 200
    except Exception:
        return jsonify({'error': 'Failed to update job status'}), 500

@app.route('/jobs/<job_id>', methods=['GET'])
def get_job_detail(job_id):
    try:
        job = supabase.table('jobs').select('title', 'description', 'status').eq('id', job_id).single().execute()
        if not job.data:
            return jsonify({'error': 'Job not found'}), 404
        return jsonify({'title': job.data['title'], 'description': job.data['description'], 'status': job.data['status']}), 200
    except Exception:
        return jsonify({'error': 'Failed to fetch job detail'}), 500

@app.route('/resumes', methods=['POST'])
def submit_resume():
    data = request.get_json()
    applicant_name = data.get('applicant_name')
    email = data.get('email')
    cv_link = data.get('cv_link')
    coverletter_link = data.get('coverletter_link')
    job_id = data.get('job_id')

    if not all([applicant_name, email, cv_link, job_id]):
        return jsonify({'error': 'Missing required fields'}), 400

    resume_data = {
        'applicant_name': applicant_name,
        'email': email,
        'cv_link': cv_link,
        'coverletter_link': coverletter_link,
        'job_id': job_id
    }
    try:
        result = supabase.table('resumes').insert(resume_data).execute()
        if not result.data:
            return jsonify({'error': 'Resume submission failed'}), 500
        return jsonify({'resume': result.data[0]}), 201
    except Exception:
        return jsonify({'error': 'Resume submission failed'}), 500

@app.route('/')
def root():
    return jsonify({'status': 'ok', 'message': 'AI Recruitment API is running.'})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)