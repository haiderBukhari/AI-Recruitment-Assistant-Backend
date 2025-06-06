import os
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, request, jsonify
from flask_cors import CORS
from evaluator import run_full_evaluation
from supabase import create_client, Client
import bcrypt
import requests
import jwt
import datetime
from middleware import get_owner_id_from_jwt
from google import genai
from google.genai import types
import io
import httpx
from verify_qstash import verify_qstash_signature

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
JWT_SECRET = os.environ.get("JWT_SECRET")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)
CORS(app) 

QSTASH_TOKEN = os.getenv("QSTASH_TOKEN")
QSTASH_ENDPOINT = "https://qstash.upstash.io/v1/publish"


def extract_text_from_pdf_url(pdf_url, prompt="Extract all text from this document exact same as it is in the document"):
    client = genai.Client()
    doc_io = io.BytesIO(httpx.get(pdf_url).content)
    sample_doc = client.files.upload(
        file=doc_io,
        config=dict(mime_type='application/pdf')
    )
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=[sample_doc, prompt]
    )
    return response.text

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
    
    # verify_qstash_signature(request)
    
    data = request.get_json()
    resume_id = data.get('resume_id', '')
    job_title = data.get('job_title', '')
    job_description = data.get('job_description', '')
    skill_condition = data.get('skill_condition', '')
    company_info = data.get('company_info', '')
    company_culture = data.get('company_culture', '')
    cv = data.get('cv', '')
    cover_letter = data.get('cover_letter', '')

    if cv and isinstance(cv, str) and cv.startswith('http'):
        try:
            cv = extract_text_from_pdf_url(cv)
        except Exception:
            cv = "Not present"
    elif not cv:
        cv = "Not present"

    if cover_letter and isinstance(cover_letter, str) and cover_letter.startswith('http'):
        try:
            cover_letter = extract_text_from_pdf_url(cover_letter)
        except Exception:
            cover_letter = "Not present"
    elif not cover_letter:
        cover_letter = "Not present"

    result = run_full_evaluation(job_title, job_description, skill_condition, company_info, cv, cover_letter, company_culture)

    if resume_id:
        update_data = {
            'company_fit_reason': result.get('company_fit_reason'),
            'company_fit_score': result.get('company_fit_score'),
            'culture_reason': result.get('culture_reason'),
            'culture_score': result.get('culture_score'),
            'experience_facts': result.get('experience_facts'),
            'experience_reason': result.get('experience_reason'),
            'experience_score': result.get('experience_score'),
            'final_recommendation': result.get('final_recommendation'),
            'level_suggestion': result.get('level_suggestion'),
            'skill_reason': result.get('skill_reason'),
            'skill_score': result.get('skill_score'),
            'total_weighted_score': result.get('total_weighted_score'),
            'evaluated': True
        }
        try:
            supabase.table('resumes').update(update_data).eq('id', resume_id).execute()
        except Exception as e:
            print(f"Failed to update resume evaluation: {e}")

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

    job = supabase.table('jobs').select('title', 'description', 'skill_condition', 'owner_id', 'total_applicants').eq('id', job_id).single().execute()

    if not job.data:
        return jsonify({'error': 'Job not found'}), 404

    job_title = job.data['title']
    job_description = job.data['description']
    skill_condition = job.data['skill_condition']
    total_applicants = job.data.get('total_applicants', 0)

    auth_data = supabase.table('authentication').select('company_details', 'company_culture').eq('id', job.data['owner_id']).single().execute()

    if not auth_data.data:
        return jsonify({'error': 'Company info not found'}), 404

    company_info = auth_data.data['company_details']
    company_culture = auth_data.data['company_culture'] 

    resume_data = {
        'applicant_name': applicant_name,
        'email': email,
        'cv_link': cv_link,
        'coverletter_link': coverletter_link,
        'job_id': job_id
    }

    try:
        result = supabase.table('resumes').insert(resume_data).execute()
        result = result.data[0]
        if not result:
            return jsonify({'error': 'Resume submission failed'}), 500

        supabase.table('jobs').update({'total_applicants': total_applicants + 1}).eq('id', job_id).execute()
        QSTASH_ENDPOINT = "https://qstash.upstash.io/v2/publish/https://talo-recruitment.vercel.app/evaluate"
        headers = {
            "Authorization": f"Bearer {QSTASH_TOKEN}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "resume_id": result['id'],
            "job_title": job_title,
            "job_description": job_description,
            "skill_condition": skill_condition,
            "company_info": company_info,
            "company_culture": company_culture,
            "cv": cv_link,
            "cover_letter": coverletter_link
        }
        response = requests.post(QSTASH_ENDPOINT, headers=headers, json=payload)
        print(QSTASH_TOKEN, response, response.text)
        return jsonify({'resume': result}), 201
    except Exception as e:
        print(e)
        return jsonify({'error': 'Resume submission failed'}), 500

@app.route('/resumes/<job_id>', methods=['GET'])
def get_resumes_for_job(job_id):
    try:
        result = supabase.table('resumes').select('*').eq('job_id', job_id).execute()
        return jsonify({'resumes': result.data}), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to fetch resumes'}), 500

@app.route('/')
def root():
    return jsonify({'status': 'ok', 'message': 'AI Recruitment API is running.'})

@app.route('/company', methods=['GET'])
def get_current_company():
    owner_id, error_response, status_code = get_owner_id_from_jwt()
    if error_response:
        return error_response, status_code
    try:
        user = supabase.table('authentication').select('id', 'full_name', 'email', 'company_name', 'company_details', 'company_culture').eq('id', owner_id).single().execute()
        if not user.data:
            return jsonify({'error': 'Company not found'}), 404
        return jsonify(user.data), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to fetch company details'}), 500

@app.route('/company', methods=['PUT'])
def update_current_company():
    owner_id, error_response, status_code = get_owner_id_from_jwt()
    if error_response:
        return error_response, status_code
    data = request.get_json()
    update_fields = {}
    for field in ['full_name', 'company_name', 'company_details', 'company_culture']:
        if field in data:
            update_fields[field] = data[field]
    if not update_fields:
        return jsonify({'error': 'No fields to update'}), 400
    try:
        result = supabase.table('authentication').update(update_fields).eq('id', owner_id).execute()
        if not result.data:
            return jsonify({'error': 'Update failed'}), 500
        return jsonify({'message': 'Company details updated', 'company': result.data[0]}), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to update company details'}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)