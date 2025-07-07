import os
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI

os.environ["GOOGLE_API_KEY"] = "AIzaSyBL6YSdMIc3FNAjSojv3Sn4ehcJonxnSik"

llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    temperature=0
)

def generate_assignment(
    job_title,
    job_description,
    skill_condition,
    company_info,
    company_culture,
    cv=None,
    cover_letter=None,
    difficulty_level="mixed"
):
    cv = cv or ""
    cover_letter = cover_letter or ""
    prompt = ChatPromptTemplate.from_template(
        """
        You are an expert technical assessment designer. Generate a comprehensive assessment for a job application based on the following details:
        
        Job Title: {job_title}
        Job Description: {job_description}
        Skill Condition: {skill_condition}
        Company Info: {company_info}
        Company Culture: {company_culture}
        Candidate CV: {cv}
        Cover Letter: {cover_letter}
        
        The assessment must include:
        - Assessment Title (key: 'title')
        - Time Limit in minutes (key: 'time_limit')
        - Description (3-4 lines, key: 'description')
        - Passing Score (key: 'passing_score')
        - Instructions for Candidates (key: 'instructions')
        - Difficulty Level (easy, medium, hard, mixed; key: 'difficulty_level')
        - 15 Questions (key: 'questions'), each question must be an object with:
            - 'question': the question text
            - 'options': a list of 4-5 options
            - 'correct_answer': the correct option (must match one of the options)
            - 'difficulty': easy, medium, or hard
        - Instructions for Passed Candidates (key: 'passed_instructions')
        
        The questions should be a mix of technical, practical, and scenario-based, and should cover all relevant areas for the job. Ensure the correct answer is always present in the options. The difficulty of the questions should match the overall difficulty_level.
        
        Respond in the following JSON format:
        {{{{
            "title": "...",
            "time_limit": <number>,
            "description": "...",
            "passing_score": <number>,
            "instructions": "...",
            "difficulty_level": "...",
            "questions": [
                {{
                    "question": "...",
                    "options": ["...", "...", ...],
                    "correct_answer": "...",
                    "difficulty": "easy|medium|hard"
                }},
                ... (total 15 questions)
            ],
            "passed_instructions": "..."
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
        "difficulty_level": difficulty_level
    }).content
    # Ensure response is a string
    if isinstance(response, list):
        response = "\n".join(str(x) for x in response)
    if not isinstance(response, str):
        response = str(response)
    response = response.strip()
    # Try to parse the response as JSON
    import json
    try:
        cleaned = response.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split('\n', 1)[-1]  # Remove the first line (``` or ```json)
            if cleaned.endswith("```"):
                cleaned = cleaned.rsplit('```', 1)[0]
        assignment = json.loads(cleaned)
    except Exception:
        assignment = {
            "title": "Assessment",
            "time_limit": 60,
            "description": "No description available.",
            "passing_score": 60,
            "instructions": "No instructions available.",
            "difficulty_level": difficulty_level,
            "questions": [],
            "passed_instructions": "No instructions available."
        }
    return assignment 