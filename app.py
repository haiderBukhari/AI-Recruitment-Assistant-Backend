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
from middleware import get_owner_id_from_jwt
from google import genai
from google.genai import types
import io
import httpx
from verify_qstash import verify_qstash_signature
from companyConfigExtractor import run_company_extraction
from flask import abort
from interviewGenerationAgent import generate_interview_questions
from interviewevaluator import evaluate_interview_performance
from datetime import datetime, timedelta
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from assignmentevaluator import evaluate_assignment_performance
from assignmentGenerationAgent import generate_assignment

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
JWT_SECRET = os.environ.get("JWT_SECRET")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)
CORS(app) 

QSTASH_TOKEN = os.getenv("QSTASH_TOKEN")
QSTASH_ENDPOINT = "https://qstash.upstash.io/v1/publish"

# Mapping from workflow step names to resume table columns
WORKFLOW_STEP_TO_COLUMN = {
    'Application Screening': 'is_screening',
    'Initial Interview': 'is_initial_interview',
    'Assessment': 'in_assessment',
    'Secondary Interview': 'is_secondary_interview',
    'Final Interview': 'in_final_interview',
    'Offer Stage': 'is_hired',
}

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
    password = data.get('password')
    company_name = data.get('company_name')
    website_url = data.get('website_url')

    if not all([full_name, email, password, company_name, website_url]):
        return jsonify({'error': 'Missing required fields'}), 400

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    user_data = {
        'full_name': full_name,
        'email': email,
        'password_hash': password_hash,
        'company_name': company_name,
        'website_url': website_url
    }
    try:
        existing = supabase.table('authentication').select('id').eq('email', email).execute()

        if existing.data:
            return jsonify({'error': 'Email already registered'}), 409

        result = supabase.table('authentication').insert(user_data).execute()
        if not result.data:
            return jsonify({'error': 'Signup failed'}), 500
        user_id = result.data[0]['id']

        # Generate JWT token after signup
        token = jwt.encode({
            'id': user_id,
            'email': email,
            'exp': datetime.utcnow() + timedelta(days=7)
        }, JWT_SECRET, algorithm='HS256')

        QSTASH_ENDPOINT = "https://qstash.upstash.io/v2/publish/https://talo-recruitment.vercel.app/fetch-company"
        headers = {
            "Authorization": f"Bearer {QSTASH_TOKEN}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "company_id": result.data[0]['id'],
            "website_url": website_url,
        }
        response = requests.post(QSTASH_ENDPOINT, headers=headers, json=payload)

    except Exception:
        return jsonify({'error': 'Signup failed'}), 500

    return jsonify({'id': user_id, 'full_name': full_name, 'email': email, 'company_name': company_name, 'website_url': website_url, 'token': token}), 201

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
        'exp': datetime.utcnow() + timedelta(days=7)
    }, JWT_SECRET, algorithm='HS256')
    return jsonify({'token': token, 'id': user_data['id']})

@app.route('/fetch-company', methods=['POST'])
def fetch_company():
    data = request.get_json()
    company_id = data.get('company_id')
    website_url = data.get('website_url')

    if not all([company_id, website_url]):
        return jsonify({'error': 'Missing company_id or website_url'}), 400

    try:
        extracted_data = run_company_extraction(website_url)

        update_data = {
            'company_description': extracted_data.get('company_description'),
            'company_details': extracted_data.get('company_details'),
            'company_culture': extracted_data.get('company_culture'),
            'company_values': extracted_data.get('company_values'),
            'linkedin': extracted_data.get('linkedin'),
            'twitter': extracted_data.get('twitter'),
            'instagram': extracted_data.get('instagram'),
            'facebook': extracted_data.get('facebook')
        }

        # Filter out any keys with None values to avoid DB errors
        update_data = {k: v for k, v in update_data.items() if v is not None}
        
        if not update_data:
            return jsonify({'error': 'No data extracted to update'}), 400

        result = supabase.table('authentication').update(update_data).eq('id', company_id).execute()
        
        if not result.data:
            return jsonify({'error': 'Failed to update company data in Supabase'}), 500

        return jsonify(extracted_data), 200

    except Exception as e:
        print(f"Error in /fetch-company: {e}")
        return jsonify({'error': 'Failed to fetch and update company data'}), 500

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
            'screening_score': result.get('total_weighted_score'),
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
        user = supabase.table('authentication').select('company_details', 'company_culture', 'company_name', 'website_url', 'company_values', 'linkedin', 'facebook', 'twitter', 'instagram', 'company_description').eq('id', owner_id).single().execute()
        if not user.data:
            return jsonify({'error': 'Company info not found'}), 404
        return jsonify({
            'company_name': user.data.get('company_name'),
            'website_url': user.data.get('website_url'),
            'company_description': user.data.get('company_description'),
            'company_details': user.data.get('company_details'),
            'company_culture': user.data.get('company_culture'),
            'company_values': user.data.get('company_values'),
            'linkedin': user.data.get('linkedin'),
            'facebook': user.data.get('facebook'),
            'twitter': user.data.get('twitter'),
            'instagram': user.data.get('instagram'),
        })
    except Exception:
        return jsonify({'error': 'Failed to fetch company info'}), 500

@app.route('/jobs', methods=['GET'])
def get_all_jobs():
    owner_id, error_response, status_code = get_owner_id_from_jwt()
    if error_response:
        return error_response, status_code
    # Accept 'stage' as a query parameter
    stage = request.args.get('stage')
    column = WORKFLOW_STEP_TO_COLUMN.get(stage) if stage else None

    try:
        result = supabase.table('jobs').select('*').eq('owner_id', owner_id).execute()
        jobs = result.data or []
        jobs_with_counts = []
        workflow = None
        next_column = None
        if column:
            try:
                workflow_result = supabase.table('workflow').select('workflow_process').eq('user_id', owner_id).single().execute()
                workflow_dict = workflow_result.data['workflow_process']

                step_keys = sorted(workflow_dict.keys(), key=lambda x: int(x.replace('step', '')))
                step_names = [workflow_dict[k] for k in step_keys]

                if stage in step_names:
                    idx = step_names.index(stage)
                    # Get next stage column if exists
                    if idx + 1 < len(step_names):
                        next_stage = step_names[idx + 1]
                        next_column = WORKFLOW_STEP_TO_COLUMN.get(next_stage)
            except Exception as e:
                pass  # If workflow not found, fallback to just current column
        for job in jobs:
            job_info = dict(job)
            if column:
                resumes_query = supabase.table('resumes').select('id')\
                    .eq('job_id', job['id'])\
                    .eq(column, True)
                if next_column:
                    resumes_query = resumes_query.eq(next_column, False)
                resumes_result = resumes_query.execute()

                count = len(resumes_result.data) if resumes_result.data else 0
                job_info['resume_count_in_stage'] = count
                job_info['stage'] = stage
            jobs_with_counts.append(job_info)
        return jsonify({'jobs': jobs_with_counts}), 200
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
    # Accept 'stage' as a query parameter
    stage = request.args.get('stage')
    column = WORKFLOW_STEP_TO_COLUMN.get(stage) if stage else None
    next_column = None
    try:
        job = supabase.table('jobs').select('title', 'description', 'status', 'owner_id').eq('id', job_id).single().execute()
        if not job.data:
            return jsonify({'error': 'Job not found'}), 404
        response = {'title': job.data['title'], 'description': job.data['description'], 'status': job.data['status']}
        if column:
            # Try to get workflow for the job's owner
            try:
                workflow_result = supabase.table('workflow').select('workflow_process').eq('user_id', job.data['owner_id']).single().execute()
                workflow_dict = workflow_result.data['workflow_process']
                step_keys = sorted(workflow_dict.keys(), key=lambda x: int(x.replace('step', '')))
                step_names = [workflow_dict[k] for k in step_keys]
                if stage in step_names:
                    idx = step_names.index(stage)
                    if idx + 1 < len(step_names):
                        next_stage = step_names[idx + 1]
                        next_column = WORKFLOW_STEP_TO_COLUMN.get(next_stage)
            except Exception:
                pass
            resumes_query = supabase.table('resumes').select('id')\
                .eq('job_id', job_id)\
                .eq(column, True)
            if next_column:
                resumes_query = resumes_query.eq(next_column, False)
            resumes_result = resumes_query.execute()
            count = len(resumes_result.data) if resumes_result.data else 0
            response['resume_count_in_stage'] = count
            response['stage'] = stage
        return jsonify(response), 200
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
    picture = data.get('picture')  # New field for candidate picture

    if not all([applicant_name, email, cv_link, job_id]):
        return jsonify({'error': 'Missing required fields'}), 400

    # Check for duplicate resume (same email and job_id)
    existing_resume = supabase.table('resumes').select('id').eq('email', email).eq('job_id', job_id).execute()
    if existing_resume.data and len(existing_resume.data) > 0:
        return jsonify({'error': 'Resume already submitted'}), 409

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
        'job_id': job_id,
        'picture': picture  # Store the picture field
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
        return jsonify({'resume': result}), 201
    except Exception as e:
        print(e)
        return jsonify({'error': 'Resume submission failed'}), 500

@app.route('/resumes/<job_id>', methods=['GET'])
def get_resumes_for_job(job_id):
    # Accept 'stage' as a query parameter
    stage = request.args.get('stage')
    column = WORKFLOW_STEP_TO_COLUMN.get(stage) if stage else None
    next_column = None
    try:
        if column:
            # Get the job to find owner_id for workflow
            job = supabase.table('jobs').select('owner_id').eq('id', job_id).single().execute()
            owner_id = job.data['owner_id'] if job and job.data else None
            if owner_id:
                try:
                    workflow_result = supabase.table('workflow').select('workflow_process').eq('user_id', owner_id).single().execute()
                    workflow_dict = workflow_result.data['workflow_process']
                    step_keys = sorted(workflow_dict.keys(), key=lambda x: int(x.replace('step', '')))
                    step_names = [workflow_dict[k] for k in step_keys]
                    if stage in step_names:
                        idx = step_names.index(stage)
                        if idx + 1 < len(step_names):
                            next_stage = step_names[idx + 1]
                            next_column = WORKFLOW_STEP_TO_COLUMN.get(next_stage)
                except Exception:
                    pass
            resumes_query = supabase.table('resumes').select('*').eq('job_id', job_id).eq(column, True)
            if next_column:
                resumes_query = resumes_query.eq(next_column, False)
            result = resumes_query.execute()
            return jsonify({'resumes': result.data}), 200
        else:
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

@app.route('/company-info', methods=['PUT'])
def update_company_info():
    owner_id, error_response, status_code = get_owner_id_from_jwt()
    if error_response:
        return error_response, status_code
    
    data = request.get_json()
    
    update_data = {}
    allowed_fields = [
        'company_description', 'company_details', 
        'company_culture', 'company_values', 'linkedin', 'facebook', 'twitter', 'instagram'
    ]
    
    for field in allowed_fields:
        if field in data:
            update_data[field] = data[field]
            
    if not update_data:
        return jsonify({'error': 'No fields to update'}), 400

    try:
        result = supabase.table('authentication').update(update_data).eq('id', owner_id).execute()
        
        if not result.data:
            return jsonify({'error': 'Failed to update company info'}), 500
            
        return jsonify({'message': 'Company info updated successfully', 'data': result.data[0]}), 200
        
    except Exception as e:
        print(f"Error updating company info: {e}")
        return jsonify({'error': 'Failed to update company info'}), 500

@app.route('/workflow', methods=['POST'])
def upsert_workflow():
    # Get JWT from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = payload.get('id')
        if not user_id:
            return jsonify({'error': 'Invalid token: no user id'}), 401
    except Exception:
        return jsonify({'error': 'Invalid or expired token'}), 401

    data = request.get_json()
    workflow_process = data.get('workflow_process')
    if workflow_process is None:
        return jsonify({'error': 'Missing workflow_process'}), 400

    try:
        existing = supabase.table('workflow').select('*').eq('user_id', user_id).single().execute()
        if existing.data:
            result = supabase.table('workflow').update({'workflow_process': workflow_process}).eq('user_id', user_id).execute()
            if not result.data:
                return jsonify({'error': 'Failed to update workflow'}), 500
            return jsonify({'workflow': result.data[0], 'action': 'updated'}), 200
        else:
            result = supabase.table('workflow').insert({'user_id': user_id, 'workflow_process': workflow_process}).execute()
            if not result.data:
                return jsonify({'error': 'Failed to create workflow'}), 500
            return jsonify({'workflow': result.data[0], 'action': 'created'}), 201
    except Exception as e:
        print(f'Error in /workflow: {e}')
        return jsonify({'error': 'Failed to upsert workflow'}), 500

@app.route('/workflow', methods=['GET'])
def get_or_create_workflow():
    # Get JWT from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = payload.get('id')
        if not user_id:
            return jsonify({'error': 'Invalid token: no user id'}), 401
    except Exception:
        return jsonify({'error': 'Invalid or expired token'}), 401

    try:
        existing = supabase.table('workflow').select('*').eq('user_id', user_id).single().execute()
        if existing.data:
            return jsonify({'workflow': existing.data}), 200
        else:
            # This block is unlikely to be reached because .single() raises if no row
            pass
    except Exception as e:
        # Check if the error is due to no row found
        error_message = str(e)
        if 'PGRST116' in error_message or 'no row' in error_message.lower():
            default_workflow = {
                'step1': 'Application Screening',
                'step2': 'Assessment',
                'step3': 'Final Interview',
                'step4': 'Offer Stage'
            }
            try:
                result = supabase.table('workflow').insert({'user_id': user_id, 'workflow_process': default_workflow}).execute()
                if not result.data:
                    return jsonify({'error': 'Failed to create default workflow'}), 500
                return jsonify({'workflow': result.data[0], 'action': 'created_default'}), 201
            except Exception as inner_e:
                print(f'Error creating default workflow: {inner_e}')
                return jsonify({'error': 'Failed to create default workflow'}), 500
        else:
            print(f'Error in GET /workflow: {e}')
            return jsonify({'error': 'Failed to get or create workflow'}), 500

@app.route('/resumes/<resume_id>/next-step', methods=['GET'])
def get_next_step(resume_id):
    # Get JWT from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = payload.get('id')
        if not user_id:
            return jsonify({'error': 'Invalid token: no user id'}), 401
    except Exception:
        return jsonify({'error': 'Invalid or expired token'}), 401

    # Get workflow for user
    try:
        workflow_result = supabase.table('workflow').select('*').eq('user_id', user_id).single().execute()
        workflow = workflow_result.data['workflow_process']
    except Exception as e:
        return jsonify({'error': 'Workflow not found for user'}), 404

    # Get resume
    try:
        resume_result = supabase.table('resumes').select('*').eq('id', resume_id).single().execute()
        resume = resume_result.data
    except Exception as e:
        return jsonify({'error': 'Resume not found'}), 404

    # Iterate through workflow steps in order
    for step_key in sorted(workflow.keys(), key=lambda x: int(x.replace('step', ''))):
        step_name = workflow[step_key]
        column = WORKFLOW_STEP_TO_COLUMN.get(step_name)
        if not column:
            continue
        # For the first step, if True, go to next; for others, if False, that's the next step
        if column == 'is_screening':
            if resume.get(column, False):
                continue
            else:
                return jsonify({'next_step': step_name}), 200
        else:
            if not resume.get(column, False):
                return jsonify({'next_step': step_name}), 200
    # If all steps are done
    return jsonify({'next_step': 'Process Complete'}), 200

@app.route('/resumes/<resume_id>/next-step', methods=['POST'])
def advance_next_step(resume_id):
    # Get JWT from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = payload.get('id')
        if not user_id:
            return jsonify({'error': 'Invalid token: no user id'}), 401
    except Exception:
        return jsonify({'error': 'Invalid or expired token'}), 401

    # Get workflow for user
    try:
        workflow_result = supabase.table('workflow').select('*').eq('user_id', user_id).single().execute()
        workflow = workflow_result.data['workflow_process']
    except Exception as e:
        return jsonify({'error': 'Workflow not found for user'}), 404

    # Get resume
    try:
        resume_result = supabase.table('resumes').select('*').eq('id', resume_id).single().execute()
        resume = resume_result.data
    except Exception as e:
        return jsonify({'error': 'Resume not found'}), 404

    # Find the next step
    for step_key in sorted(workflow.keys(), key=lambda x: int(x.replace('step', ''))):
        step_name = workflow[step_key]
        column = WORKFLOW_STEP_TO_COLUMN.get(step_name)
        if not column:
            continue
        if column == 'is_screening':
            if resume.get(column, False):
                continue
            else:
                # Advance this step
                update = {column: True}
                result = supabase.table('resumes').update(update).eq('id', resume_id).execute()
                return jsonify({'updated_resume': result.data[0], 'current_step': step_name}), 200
        else:
            if not resume.get(column, False):
                update = {column: True}
                result = supabase.table('resumes').update(update).eq('id', resume_id).execute()
                return jsonify({'updated_resume': result.data[0], 'current_step': step_name}), 200
    # If all steps are done
    return jsonify({'message': 'Process Complete'}), 200

@app.route('/interview/generate', methods=['POST'])
def generate_interview():
    data = request.get_json()
    resume_id = data.get('resume_id')
    stage = data.get('stage')
    if not resume_id or not stage:
        return jsonify({'error': 'Missing resume_id or stage'}), 400
    # Fetch resume and job info
    try:
        resume = supabase.table('resumes').select('*').eq('id', resume_id).single().execute().data
        if not resume:
            return jsonify({'error': 'Resume not found'}), 404
        job = supabase.table('jobs').select('*').eq('id', resume['job_id']).single().execute().data
        if not job:
            return jsonify({'error': 'Job not found'}), 404
        auth = supabase.table('authentication').select('company_details', 'company_culture').eq('id', job['owner_id']).single().execute().data
        company_info = auth.get('company_details', '') if auth else ''
        company_culture = auth.get('company_culture', '') if auth else ''
        # Gather previous questions and suggestions
        previous_questions = {}
        previous_suggestions = {}
        if stage == 'Initial Interview':
            if resume.get('initial_interview_question'):
                previous_questions['initial_interview'] = resume.get('initial_interview_question')
            if resume.get('initial_interview_suggestion'):
                previous_suggestions['initial_interview'] = resume.get('initial_interview_suggestion')
        elif stage == 'Secondary Interview':
            if resume.get('initial_interview_question'):
                previous_questions['initial_interview'] = resume.get('initial_interview_question')
            if resume.get('scondary_interview_question'):
                previous_questions['secondary_interview'] = resume.get('scondary_interview_question')
            if resume.get('initial_interview_suggestion'):
                previous_suggestions['initial_interview'] = resume.get('initial_interview_suggestion')
            if resume.get('scondary_interview_suggestion'):
                previous_suggestions['secondary_interview'] = resume.get('scondary_interview_suggestion')
        elif stage == 'Final Interview':
            if resume.get('initial_interview_question'):
                previous_questions['initial_interview'] = resume.get('initial_interview_question')
            if resume.get('scondary_interview_question'):
                previous_questions['secondary_interview'] = resume.get('scondary_interview_question')
            if resume.get('final_interview_question'):
                previous_questions['final_interview'] = resume.get('final_interview_question')
            if resume.get('initial_interview_suggestion'):
                previous_suggestions['initial_interview'] = resume.get('initial_interview_suggestion')
            if resume.get('scondary_interview_suggestion'):
                previous_suggestions['secondary_interview'] = resume.get('scondary_interview_suggestion')
            if resume.get('final_interview_suggestion'):
                previous_suggestions['final_interview'] = resume.get('final_interview_suggestion')
        questions = generate_interview_questions(
            job_title=job.get('title', ''),
            job_description=job.get('description', ''),
            skill_condition=job.get('skill_condition', ''),
            company_info=company_info,
            company_culture=company_culture,
            cv=resume.get('cv_link', ''),
            cover_letter=resume.get('coverletter_link', ''),
            stage=stage,
            previous_questions=previous_questions,
            previous_suggestions=previous_suggestions
        )
        # Determine which field to update
        field_map = {
            'Initial Interview': 'initial_interview_question',
            'Final Interview': 'final_interview_question',
            'Secondary Interview': 'scondary_interview_question',
        }
        question_field = field_map.get(stage)
        if question_field:
            supabase.table('resumes').update({question_field: questions}).eq('id', resume_id).execute()
        return jsonify({'questions': questions}), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to generate interview questions'}), 500

@app.route('/interview/schedule', methods=['POST'])
def schedule_interview():
    data = request.get_json()
    resume_id = data.get('resume_id')
    stage = data.get('stage')
    schedule = data.get('schedule')  # Expecting a dict with date, time, meet_link, notes (optional)
    if not resume_id or not stage or not schedule:
        return jsonify({'error': 'Missing resume_id, stage, or schedule'}), 400
    # Validate required fields in schedule
    date = schedule.get('date')
    time = schedule.get('time')
    meet_link = schedule.get('meet_link')
    notes = schedule.get('notes', '')
    if not date or not time or not meet_link:
        return jsonify({'error': 'Missing date, time, or meet_link in schedule'}), 400
    # Determine which field to update
    field_map = {
        'Initial Interview': 'initial_interview_schedule',
        'Final Interview': 'final_interview_schedule',
        'Secondary Interview': 'scondary_interview_schedule',
    }
    schedule_field = field_map.get(stage)
    if not schedule_field:
        return jsonify({'error': 'Invalid stage for scheduling'}), 400
    try:
        # Store the whole schedule JSON
        supabase.table('resumes').update({schedule_field: schedule}).eq('id', resume_id).execute()
        return jsonify({'message': f'{stage} scheduled', 'schedule': schedule}), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to schedule interview'}), 500

@app.route('/add-interview-details', methods=['POST'])
def add_interview_details():
    data = request.get_json()
    resume_id = data.get('resume_id')
    details = data.get('details')  # JSON object
    if not resume_id or details is None:
        return jsonify({'error': 'Missing resume_id or details'}), 400
    try:
        # Fetch resume
        resume = supabase.table('resumes').select('*').eq('id', resume_id).single().execute().data
        if not resume:
            return jsonify({'error': 'Resume not found'}), 404
        stage = data.get('stage') or details.get('stage')
        if not stage:
            return jsonify({'error': 'Missing stage'}), 400
        # Determine which field to update
        field_map = {
            'Initial Interview': 'initial_details',
            'Final Interview': 'final_details',
            'Secondary Interview': 'secondary_details',
        }
        score_field_map = {
            'Initial Interview': 'initial_interview_score',
            'Final Interview': 'final_interview_score',
            'Secondary Interview': 'scondary_interview_score',
        }
        suggestion_field_map = {
            'Initial Interview': 'initial_interview_suggestion',
            'Final Interview': 'final_interview_suggestion',
            'Secondary Interview': 'scondary_interview_suggestion',
        }
        details_field = field_map.get(stage)
        score_field = score_field_map.get(stage)
        suggestion_field = suggestion_field_map.get(stage)
        if not details_field or not score_field or not suggestion_field:
            return jsonify({'error': 'Invalid stage for interview details'}), 400
        # Get total_weighted_score and previous interview scores
        total_weighted_score = resume.get('total_weighted_score', 0)
        prev_scores = []
        if stage == 'Initial Interview':
            prev_scores = []
        elif stage == 'Secondary Interview':
            prev_scores = [resume.get('initial_interview_score', 0)]
        elif stage == 'Final Interview':
            prev_scores = [resume.get('initial_interview_score', 0), resume.get('scondary_interview_score', 0)]
        # Get job info
        job = supabase.table('jobs').select('title', 'description', 'skill_condition').eq('id', resume['job_id']).single().execute().data
        job_title = job.get('title', '') if job else ''
        job_description = job.get('description', '') if job else ''
        skill_condition = job.get('skill_condition', '') if job else ''
        # Save details
        supabase.table('resumes').update({details_field: details}).eq('id', resume_id).execute()
        # Evaluate and update score and suggestion
        eval_result = evaluate_interview_performance(
            stage, details, total_weighted_score, prev_scores, job_title, job_description, skill_condition
        )
        supabase.table('resumes').update({score_field: eval_result['score'], suggestion_field: eval_result['suggestion']}).eq('id', resume_id).execute()
        # Update total_weighted_score with the new score
        supabase.table('resumes').update({'total_weighted_score': eval_result['score']}).eq('id', resume_id).execute()
        return jsonify({'message': f'{stage} details added', 'details': details, 'score': eval_result['score'], 'suggestion': eval_result['suggestion']}), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to add interview details'}), 500

@app.route('/interviews', methods=['GET'])
def get_interviews():
    owner_id, error_response, status_code = get_owner_id_from_jwt()
    if error_response:
        return error_response, status_code
    # Accept 'stage' as a query parameter
    stage = request.args.get('stage')
    stages_param = request.args.get('stages')
    stages_list = [s.strip() for s in stages_param.split(',')] if stages_param else None
    column = WORKFLOW_STEP_TO_COLUMN.get(stage) if stage else None
    next_column = None
    try:
        # Get all jobs for the user
        jobs_result = supabase.table('jobs').select('id', 'title').eq('owner_id', owner_id).execute()
        jobs = jobs_result.data or []
        job_map = {job['id']: job for job in jobs}
        # Get stage order from workflow for the user
        workflow_result = supabase.table('workflow').select('workflow_process').eq('user_id', owner_id).single().execute()
        workflow_dict = workflow_result.data['workflow_process']
        step_keys = sorted(workflow_dict.keys(), key=lambda x: int(x.replace('step', '')))
        stage_order_names = [workflow_dict[k] for k in step_keys]
        # Map stage names to boolean and schedule fields
        stage_to_bool = {
            'Application Screening': 'is_screening',
            'Initial Interview': 'is_initial_interview',
            'Secondary Interview': 'is_secondary_interview',
            'Assessment': 'in_assessment',
            'Final Interview': 'in_final_interview',
            'Offer Stage': 'is_hired',
        }
        stage_to_schedule = {
            'Initial Interview': 'initial_interview_schedule',
            'Secondary Interview': 'scondary_interview_schedule',
            'Final Interview': 'final_interview_schedule',
        }
        # Build dynamic stage order for logic
        stage_order = []
        for s in stage_order_names:
            stage_order.append((s, stage_to_bool.get(s), stage_to_schedule.get(s)))
        # If stage is provided, get workflow for the user to determine next_column
        if column:
            try:
                idx = stage_order_names.index(stage)
                if idx + 1 < len(stage_order_names):
                    next_stage = stage_order_names[idx + 1]
                    next_column = stage_to_bool.get(next_stage)
            except Exception:
                pass
        # Get all resumes for these jobs, but filter by stage if provided
        job_ids = [job['id'] for job in jobs]
        if not job_ids:
            response = jsonify({'upcoming_interviews': [], 'past_interviews': []})
            response.status_code = 200
            return response
        if column:
            resumes_query = supabase.table('resumes').select('*').in_('job_id', job_ids).eq(column, True)
            if next_column:
                # Accept both False and None for next_column (correct syntax)
                resumes_query = resumes_query.or_(f"{next_column}.eq.false,{next_column}.is.null")
            resumes_result = resumes_query.execute()
            resumes = resumes_result.data or []
        else:
            resumes_result = supabase.table('resumes').select('*').in_('job_id', job_ids).execute()
            resumes = resumes_result.data or []
        # Now, continue with the rest of the logic as before
        upcoming_interviews = []
        past_interviews = []
        now = datetime.now()
        for resume in resumes:
            # Find current stage using next-stage methodology
            current_stage = None
            next_stage = None
            for idx, (s, col_s, _) in enumerate(stage_order):
                if resume.get(col_s):
                    if idx + 1 == len(stage_order) or not resume.get(stage_order[idx + 1][1]):
                        current_stage = s
                        next_stage = stage_order[idx + 1][0] if idx + 1 < len(stage_order) else None
                        break
            # If stages_list is provided, only process resumes whose current_stage is in stages_list
            if stages_list and (not current_stage or current_stage not in stages_list):
                continue
            # Only check the schedule for the current stage
            schedule_field = stage_to_schedule.get(current_stage)
            if schedule_field and resume.get(schedule_field):
                schedule = resume[schedule_field]
                date_str = schedule.get('date')
                time_str = schedule.get('time')
                if date_str and time_str:
                    try:
                        dt_str = f"{date_str} {time_str}"
                        try:
                            interview_dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M")
                        except Exception:
                            interview_dt = datetime.strptime(dt_str, "%Y-%m-%d %I:%M %p")
                    except Exception:
                        interview_dt = None
                    interview_info = {
                        'job_id': resume['job_id'],
                        'job_title': job_map.get(resume['job_id'], {}).get('title', ''),
                        'resume_id': resume['id'],
                        'applicant_name': resume.get('applicant_name', ''),
                        'email': resume.get('email', ''),
                        'stage': current_stage,
                        'schedule': schedule,
                        'current_stage': current_stage,
                        'next_stage': next_stage
                    }
                    if interview_dt:
                        if interview_dt >= now:
                            upcoming_interviews.append(interview_info)
                        else:
                            past_interviews.append(interview_info)
        response = jsonify({'upcoming_interviews': upcoming_interviews, 'past_interviews': past_interviews})
        response.status_code = 200
        return response
    except Exception as e:
        print(e)
        response = jsonify({'error': 'Failed to fetch interviews'})
        response.status_code = 500
        return response

@app.route('/jobs/<job_id>/assessments/candidates', methods=['GET'])
def get_assessment_candidates(job_id):
    # Accept 'stage' as a query parameter, default to 'Assessment'
    stage = request.args.get('stage', 'Assessment')
    column = WORKFLOW_STEP_TO_COLUMN.get(stage)
    if not column:
        return jsonify({'error': 'Invalid or missing stage'}), 400
    try:
        # Get job info for title and owner_id
        job_result = supabase.table('jobs').select('title', 'owner_id').eq('id', job_id).single().execute()
        if not job_result or not job_result.data:
            return jsonify({'error': 'Job not found'}), 404
        job_title = job_result.data['title']
        owner_id = job_result.data['owner_id']
        # Get workflow for the job's owner
        workflow_result = supabase.table('workflow').select('workflow_process').eq('user_id', owner_id).single().execute()
        workflow_dict = workflow_result.data['workflow_process']
        step_keys = sorted(workflow_dict.keys(), key=lambda x: int(x.replace('step', '')))
        step_names = [workflow_dict[k] for k in step_keys]
        # Find index of current stage
        next_column = None
        if stage in step_names:
            idx = step_names.index(stage)
            if idx + 1 < len(step_names):
                next_stage = step_names[idx + 1]
                next_column = WORKFLOW_STEP_TO_COLUMN.get(next_stage)
        # Query resumes where current stage is True and next stage is False or None
        resumes_query = supabase.table('resumes').select('*').eq('job_id', job_id).eq(column, True)
        if next_column:
            resumes_query = resumes_query.or_(f"{next_column}.eq.false,{next_column}.is.null")
        resumes_result = resumes_query.execute()
        resumes = resumes_result.data or []
        candidates = []
        for resume in resumes:
            candidate = {
                'candidate_name': resume.get('applicant_name') or resume.get('full_name') or resume.get('applicant_name', ''),
                'email': resume.get('email', ''),
                'id': resume.get('id', ''),
                'job_title': job_title,
                'status': resume.get('status', ''),
                'score': resume.get('score'),
                'time_spent': resume.get('time_spent'),
                'assignment_sent': resume.get('assignment_sent'),
                'assignment_submission': resume.get('assignment_submission'),
                'assignment_submission_link': resume.get('assignment_submission_link'),
                'assignment_template': resume.get('assignment_template'),
                'assignment_feedback': resume.get('assignment_feedback'),
            }
            candidates.append(candidate)
        return jsonify({'candidates': candidates}), 200
    except Exception as e:
        print(f"Error in get_assessment_candidates: {e}")
        return jsonify({'error': 'Failed to fetch assessment candidates'}), 500

@app.route('/assessments/create', methods=['POST'])
def create_assessment():
    data = request.get_json()
    resume_id = data.get('resume_id')
    details = data.get('details')  # JSON object for assignment_template
    if not resume_id or details is None:
        return jsonify({'error': 'Missing resume_id or details'}), 400
    try:
        # Set assignment_sent to now
        from datetime import datetime
        assignment_sent = datetime.utcnow().isoformat() + 'Z'
        # Fetch current assignment_template (could be None)
        resume_result = supabase.table('resumes').select('assignment_template', 'email', 'job_id', 'applicant_name').eq('id', resume_id).single().execute()
        assignment_template = resume_result.data.get('assignment_template') if resume_result and resume_result.data else None
        receiver_email = resume_result.data.get('email') if resume_result and resume_result.data else None
        if not receiver_email:
            return jsonify({'error': 'Candidate email not found'}), 404
        # If assignment_template is not a list, make it a list
        if not isinstance(assignment_template, list):
            assignment_template = []
        # Append new details
        assignment_template.append(details)
        # Update the resume
        update_data = {
            'assignment_sent': assignment_sent,
            'assignment_template': assignment_template
        }
        result = supabase.table('resumes').update(update_data).eq('id', resume_id).execute()
        if not result.data:
            return jsonify({'error': 'Failed to create assessment'}), 500
        # Send email notification to candidate
        sender_email = os.environ.get('SENDER_EMAIL')
        app_password = os.environ.get('APP_PASSWORD')
        candidate_name = resume_result.data.get('applicant_name') or resume_result.data.get('full_name') or resume_result.data.get('applicant_name', '')
        job_id = resume_result.data.get('job_id')
        job_title = ''
        if job_id:
            job_result = supabase.table('jobs').select('title').eq('id', job_id).single().execute()
            if job_result and job_result.data:
                job_title = job_result.data.get('title', '')
        assignment_title = details.get('title', 'Assignment')
        assignment_description = details.get('description', '')
        assignment_deadline = details.get('deadline', '')
        subject = f"Assignment for your job application: {job_title}"
        assignment_link = f"https://talohr.vercel.app/viewassignment/{resume_id}"
        body = f"Hello {candidate_name},\n\nYou have received a new assignment as part of your application for the position of {job_title}.\n\nAssignment Title: {assignment_title}\nDescription: {assignment_description}\n"
        if assignment_deadline:
            body += f"Deadline: {assignment_deadline}\n"
        body += f"\nPlease view and complete your assignment at the following link:\n{assignment_link}\n\nBest regards,\nYour Recruitment Team\n"
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))
        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(sender_email, app_password)
                server.send_message(message)
        except Exception as email_error:
            print(f"Failed to send assignment email: {email_error}")
            # Do not fail the API if email fails, just log
        return jsonify({'message': 'Assessment created and email sent', 'resume': result.data[0]}), 201
    except Exception as e:
        print(f"Error in create_assessment: {e}")
        return jsonify({'error': 'Failed to create assessment'}), 500

@app.route('/assignments/<resume_id>', methods=['GET'])
def get_assignment(resume_id):
    try:
        result = supabase.table('resumes').select('assignment_template', 'assignment_sent', 'assignment_submission', 'assignment_submission_link').eq('id', resume_id).single().execute()
        if not result or not result.data:
            return jsonify({'error': 'Assignment not found'}), 404
        data = result.data
        submitted = bool(data.get('assignment_submission') or data.get('assignment_submission_link'))
        return jsonify({
            'assignment_template': data.get('assignment_template'),
            'assignment_sent': data.get('assignment_sent'),
            'assignment_submission': data.get('assignment_submission'),
            'assignment_submission_link': data.get('assignment_submission_link'),
            'submitted': submitted
        }), 200
    except Exception as e:
        print(f"Error in get_assignment: {e}")
        return jsonify({'error': 'Failed to fetch assignment'}), 500

@app.route('/assignments/<resume_id>', methods=['PUT'])
def edit_assignment(resume_id):
    data = request.get_json()
    details = data.get('details')
    if not details:
        return jsonify({'error': 'Missing details'}), 400
    try:
        # Fetch current assignment_template
        resume_result = supabase.table('resumes').select('assignment_template').eq('id', resume_id).single().execute()
        assignment_template = resume_result.data.get('assignment_template') if resume_result and resume_result.data else None
        if not assignment_template or not isinstance(assignment_template, list) or len(assignment_template) == 0:
            # If no assignment exists, add as first
            assignment_template = [details]
        else:
            # Update the last assignment
            assignment_template[-1] = details
        # Optionally update assignment_sent to now
        assignment_sent = datetime.utcnow().isoformat() + 'Z'
        update_data = {
            'assignment_template': assignment_template,
            'assignment_sent': assignment_sent
        }
        result = supabase.table('resumes').update(update_data).eq('id', resume_id).execute()
        if not result.data:
            return jsonify({'error': 'Failed to update assignment'}), 500
        return jsonify({'message': 'Assignment updated', 'assignment_template': assignment_template}), 200
    except Exception as e:
        print(f"Error in edit_assignment: {e}")
        return jsonify({'error': 'Failed to update assignment'}), 500

@app.route('/assignments/<resume_id>/submit', methods=['POST'])
def submit_assignment(resume_id):
    data = request.get_json()
    submission_details = data.get('details')
    if not submission_details:
        return jsonify({'error': 'Missing submission details'}), 400
    try:
        # Set assignment_submission to now
        assignment_submission = datetime.utcnow().isoformat() + 'Z'
        # Fetch current full_assignment_submission and assignment_template, job_id, total_weighted_score
        resume_result = supabase.table('resumes').select('full_assignment_submission', 'assignment_template', 'job_id', 'total_weighted_score').eq('id', resume_id).single().execute()
        data_row = resume_result.data if resume_result and resume_result.data else {}
        full_assignment_submission = data_row.get('full_assignment_submission')
        if not isinstance(full_assignment_submission, list):
            full_assignment_submission = []
        full_assignment_submission.append(submission_details)
        assignment_template = data_row.get('assignment_template')
        job_id = data_row.get('job_id')
        total_weighted_score = data_row.get('total_weighted_score', 0)
        # Fetch job info
        job_title = ''
        job_description = ''
        if job_id:
            job_result = supabase.table('jobs').select('title', 'description').eq('id', job_id).single().execute()
            if job_result and job_result.data:
                job_title = job_result.data.get('title', '')
                job_description = job_result.data.get('description', '')
        # Evaluate assignment
        eval_result = evaluate_assignment_performance(
            job_title=job_title,
            job_description=job_description,
            assignment_template=assignment_template,
            full_assignment_submission=full_assignment_submission,
            total_weighted_score=total_weighted_score
        )
        # Update resume with evaluation
        update_data = {
            'assignment_submission': assignment_submission,
            'full_assignment_submission': full_assignment_submission,
            'assignment_feedback': eval_result.get('assignment_feedback'),
            'score': eval_result.get('score'),
            'total_weighted_score': eval_result.get('total_weighted_score')
        }
        result = supabase.table('resumes').update(update_data).eq('id', resume_id).execute()
        if not result.data:
            return jsonify({'error': 'Failed to submit assignment'}), 500
        return jsonify({
            'message': 'Assignment submitted and evaluated',
            'assignment_submission': assignment_submission,
            'full_assignment_submission': full_assignment_submission,
            'assignment_feedback': eval_result.get('assignment_feedback'),
            'score': eval_result.get('score'),
            'total_weighted_score': eval_result.get('total_weighted_score')
        }), 200
    except Exception as e:
        print(f"Error in submit_assignment: {e}")
        return jsonify({'error': 'Failed to submit assignment'}), 500

@app.route('/assignments/<resume_id>/submitted', methods=['GET'])
def get_submitted_assignment(resume_id):
    try:
        result = supabase.table('resumes').select('assignment_submission', 'full_assignment_submission', 'assignment_template', 'assignment_feedback', 'score', 'total_weighted_score').eq('id', resume_id).single().execute()
        if not result or not result.data:
            return jsonify({'error': 'Submitted assignment not found'}), 404
        data = result.data
        return jsonify({
            'assignment_submission': data.get('assignment_submission'),
            'full_assignment_submission': data.get('full_assignment_submission'),
            'assignment_template': data.get('assignment_template'),
            'assignment_feedback': data.get('assignment_feedback'),
            'score': data.get('score'),
            'total_weighted_score': data.get('total_weighted_score')
        }), 200
    except Exception as e:
        print(f"Error in get_submitted_assignment: {e}")
        return jsonify({'error': 'Failed to fetch submitted assignment'}), 500

@app.route('/offers/candidates', methods=['GET'])
def get_offer_stage_candidates():
    # Get JWT from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = payload.get('id')
        if not user_id:
            return jsonify({'error': 'Invalid token: no user id'}), 401
    except Exception:
        return jsonify({'error': 'Invalid or expired token'}), 401
    try:
        # Get all jobs owned by this user
        jobs_result = supabase.table('jobs').select('id').eq('owner_id', user_id).execute()
        job_ids = [job['id'] for job in jobs_result.data] if jobs_result and jobs_result.data else []
        if not job_ids:
            return jsonify({'candidates': []}), 200
        # Get all resumes in offer stage for these jobs
        resumes_result = supabase.table('resumes').select('*').in_('job_id', job_ids).eq('in_final_interview', True).eq('is_hired', True).execute()
        resumes = resumes_result.data or []
        candidates = []
        for resume in resumes:
            candidate = dict(resume)
            candidate['offer_details'] = resume.get('offer_details')
            candidates.append(candidate)
        return jsonify({'candidates': candidates}), 200
    except Exception as e:
        print(f"Error in get_offer_stage_candidates: {e}")
        return jsonify({'error': 'Failed to fetch offer stage candidates'}), 500

@app.route('/offers/make', methods=['POST'])
def make_offer():
    data = request.get_json()
    resume_id = data.get('resume_id')
    offer_details = data.get('offer_details')
    if not resume_id or offer_details is None:
        return jsonify({'error': 'Missing resume_id or offer_details'}), 400
    try:
        # Get JWT from Authorization header
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = payload.get('id')
        if not user_id:
            return jsonify({'error': 'Invalid token: no user id'}), 401
        # Fetch the resume and check job ownership
        resume_result = supabase.table('resumes').select('job_id').eq('id', resume_id).single().execute()
        if not resume_result or not resume_result.data:
            return jsonify({'error': 'Resume not found'}), 404
        job_id = resume_result.data.get('job_id')
        job_result = supabase.table('jobs').select('owner_id').eq('id', job_id).single().execute()
        if not job_result or not job_result.data or job_result.data.get('owner_id') != user_id:
            return jsonify({'error': 'Unauthorized: not your job'}), 403
        # Update the resume with offer_details
        update_result = supabase.table('resumes').update({'offer_details': offer_details}).eq('id', resume_id).execute()
        if not update_result or not update_result.data:
            return jsonify({'error': 'Failed to update offer details'}), 500
        return jsonify({'message': 'Offer made', 'resume': update_result.data[0]}), 200
    except Exception as e:
        print(f"Error in make_offer: {e}")
        return jsonify({'error': 'Failed to make offer'}), 500

@app.route('/candidates/all', methods=['GET'])
def get_all_candidates():
    # Get JWT from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = payload.get('id')
        if not user_id:
            return jsonify({'error': 'Invalid token: no user id'}), 401
    except Exception:
        return jsonify({'error': 'Invalid or expired token'}), 401
    try:
        # Get all jobs owned by this user
        jobs_result = supabase.table('jobs').select('id').eq('owner_id', user_id).execute()
        job_ids = [job['id'] for job in jobs_result.data] if jobs_result and jobs_result.data else []
        if not job_ids:
            return jsonify({'candidates': []}), 200
        # Get all resumes for these jobs
        resumes_result = supabase.table('resumes').select('*').in_('job_id', job_ids).execute()
        resumes = resumes_result.data or []
        candidates = []
        for resume in resumes:
            candidate = dict(resume)
            candidate['offer_details'] = resume.get('offer_details')
            candidates.append(candidate)
        return jsonify({'candidates': candidates}), 200
    except Exception as e:
        print(f"Error in get_all_candidates: {e}")
        return jsonify({'error': 'Failed to fetch candidates'}), 500

# @app.route('/jobs/total', methods=['GET'])
# def get_total_jobs():
#     # Get JWT from Authorization header
#     auth_header = request.headers.get('Authorization', '')
#     if not auth_header.startswith('Bearer '):
#         return jsonify({'error': 'Missing or invalid Authorization header'}), 401
#     token = auth_header.split(' ')[1]
#     try:
#         payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
#         user_id = payload.get('id')
#         if not user_id:
#             return jsonify({'error': 'Invalid token: no user id'}), 401
#     except Exception:
#         return jsonify({'error': 'Invalid or expired token'}), 401
#     try:
#         jobs_result = supabase.table('jobs').select('id').eq('owner_id', user_id).execute()
#         total_jobs = len(jobs_result.data) if jobs_result and jobs_result.data else 0
#         return jsonify({'total_jobs': total_jobs}), 200
#     except Exception as e:
#         print(f"Error in get_total_jobs: {e}")
#         return jsonify({'error': 'Failed to fetch total jobs'}), 500

@app.route('/candidates/<resume_id>', methods=['GET'])
def get_single_candidate(resume_id):
    # Get JWT from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = payload.get('id')
        if not user_id:
            return jsonify({'error': 'Invalid token: no user id'}), 401
    except Exception:
        return jsonify({'error': 'Invalid or expired token'}), 401
    try:
        # Fetch the resume
        resume_result = supabase.table('resumes').select('*').eq('id', resume_id).single().execute()
        if not resume_result or not resume_result.data:
            return jsonify({'error': 'Candidate not found'}), 404
        resume = dict(resume_result.data)
        resume['offer_details'] = resume.get('offer_details')
        return jsonify({'candidate': resume}), 200
    except Exception as e:
        print(f"Error in get_single_candidate: {e}")
        return jsonify({'error': 'Failed to fetch candidate'}), 500

@app.route('/jobs/total', methods=['GET'])
def get_all_jobs_details():
    # Get JWT from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = payload.get('id')
        if not user_id:
            return jsonify({'error': 'Invalid token: no user id'}), 401
    except Exception:
        return jsonify({'error': 'Invalid or expired token'}), 401
    try:
        jobs_result = supabase.table('jobs').select('*').eq('owner_id', user_id).execute()
        jobs = jobs_result.data if jobs_result and jobs_result.data else []
        return jsonify({'jobs': jobs}), 200
    except Exception as e:
        print(f"Error in get_all_jobs_details: {e}")
        return jsonify({'error': 'Failed to fetch jobs'}), 500

@app.route('/assignment/generate', methods=['POST'])
def generate_assignment_api():
    data = request.get_json()
    resume_id = data.get('resume_id')
    difficulty_level = data.get('difficulty_level', 'mixed')
    instructions = data.get('instructions', None)
    if not resume_id:
        return jsonify({'error': 'Missing resume_id'}), 400
    try:
        # Fetch resume
        resume_result = supabase.table('resumes').select('*').eq('id', resume_id).single().execute()
        resume = resume_result.data if resume_result and resume_result.data else None
        if not resume:
            return jsonify({'error': 'Resume not found'}), 404
        job_id = resume.get('job_id')
        if not job_id:
            return jsonify({'error': 'Job ID not found in resume'}), 404
        # Fetch job
        job_result = supabase.table('jobs').select('title', 'description', 'skill_condition', 'owner_id').eq('id', job_id).single().execute()
        job = job_result.data if job_result and job_result.data else None
        if not job:
            return jsonify({'error': 'Job not found'}), 404
        # Fetch company info
        auth_result = supabase.table('authentication').select('company_details', 'company_culture').eq('id', job['owner_id']).single().execute()
        auth = auth_result.data if auth_result and auth_result.data else None
        company_info = auth.get('company_details', '') if auth else ''
        company_culture = auth.get('company_culture', '') if auth else ''
        # Generate assignment
        assignment = generate_assignment(
            job_title=job.get('title', ''),
            job_description=job.get('description', ''),
            skill_condition=job.get('skill_condition', ''),
            company_info=company_info,
            company_culture=company_culture,
            difficulty_level=difficulty_level
        )
        # If instructions are provided, override
        if instructions:
            assignment['instructions'] = instructions
        return jsonify({'assignment': assignment}), 200
    except Exception as e:
        print(f"Error in generate_assignment_api: {e}")
        return jsonify({'error': 'Failed to generate assignment'}), 500


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
