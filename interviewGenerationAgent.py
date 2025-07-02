import os
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI

os.environ["GOOGLE_API_KEY"] = "AIzaSyBL6YSdMIc3FNAjSojv3Sn4ehcJonxnSik"

llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    temperature=0
)

def generate_interview_questions(job_title, job_description, skill_condition, company_info, company_culture, cv, cover_letter, stage):
    prompt = ChatPromptTemplate.from_template(
        f"""
        You are an expert technical interviewer. Generate a set of interview questions for the following interview stage: {{stage}}.
        The questions should be tailored to the candidate's background and the job requirements.
        
        Job Title: {{job_title}}
        Job Description: {{job_description}}
        Skill Condition: {{skill_condition}}
        Company Info: {{company_info}}
        Company Culture: {{company_culture}}
        Candidate CV: {{cv}}
        Cover Letter: {{cover_letter}}
        
        Please generate:
        - At least 10 Job-Related Questions (key: 'job'), ranging from easy to complex, covering all relevant technical and role-specific areas.
        - At least 6 Prior Experience Questions (key: 'prior_experience'), from basic to advanced, focusing on the candidate's past roles, achievements, and relevant experience.
        - At least 6 Soft Skills & Behavioral Questions (key: 'soft_skills'), from basic to advanced, covering teamwork, communication, leadership, and problem-solving.
        
        All lists must be non-empty and cover a range of difficulty.
        
        Respond in the following JSON format:
        {{{{
            "job": ["...", "...", ...],
            "prior_experience": ["...", ...],
            "soft_skills": ["...", ...]
        }}}}
        """
    )
    response = (prompt | llm).invoke({
        "job_title": job_title,
        "job_description": job_description,
        "skill_condition": skill_condition,
        "company_info": company_info,
        "company_culture": company_culture,
        "cv": cv,
        "cover_letter": cover_letter,
        "stage": stage
    }).content.strip()
    # Try to parse the response as JSON
    import json
    try:
        cleaned = response.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split('\n', 1)[-1]  # Remove the first line (``` or ```json)
            if cleaned.endswith("```"):
                cleaned = cleaned.rsplit('```', 1)[0]
        questions = json.loads(cleaned)
    except Exception:
        questions = {"job": [], "prior_experience": [], "soft_skills": []}
    return questions 