import os
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
import json

os.environ["GOOGLE_API_KEY"] = "AIzaSyBL6YSdMIc3FNAjSojv3Sn4ehcJonxnSik"

llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    temperature=0
)

def evaluate_assignment_performance(job_title, job_description, assignment_template, full_assignment_submission, total_weighted_score):
    assignment_template_str = json.dumps(assignment_template, indent=2)
    submission_str = json.dumps(full_assignment_submission, indent=2)
    prompt = ChatPromptTemplate.from_template(
        f"""
        You are an expert technical evaluator. Evaluate the following candidate's assignment submission for a job application.
        
        Job Title: {{job_title}}
        Job Description: {{job_description}}
        Assignment Template (JSON):
        {{assignment_template_str}}
        
        Candidate's Submission (JSON):
        {{submission_str}}
        
        For any file URLs (such as PDFs), you may assume you have access to their content. Evaluate the answers, uploaded files, and all provided information.
        
        The assignment score you provide (key: 'score') is out of 100 and reflects only the assignment. However, the assignment section contributes only 30% to the candidate's overall total_weighted_score (out of 100). When updating total_weighted_score, you may only adjust the 30% portion that comes from the assignment, while the other 70% remains unchanged. The candidate's current overall score is represented by total_weighted_score: {{total_weighted_score}} (out of 100).
        
        Please provide:
        - An updated score from 0 to 100 for this assignment (key: 'score')
        - A brief feedback (2-4 lines, key: 'assignment_feedback')
        - An updated total_weighted_score (key: 'total_weighted_score', out of 100) that reflects only the assignment's 30% weight, with the other 70% unchanged.
        
        Respond in the following JSON format:
        {{{{
            "score": <number>,
            "assignment_feedback": "...",
            "total_weighted_score": <number>
        }}}}
        """
    )
    response = (prompt | llm).invoke({
        "job_title": job_title,
        "job_description": job_description,
        "assignment_template_str": assignment_template_str,
        "submission_str": submission_str,
        "total_weighted_score": total_weighted_score
    }).content
    # Ensure response is a string
    if isinstance(response, list):
        response = "\n".join(str(x) for x in response)
    if not isinstance(response, str):
        response = str(response)
    response = response.strip()
    try:
        cleaned = response.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split('\n', 1)[-1]
            if cleaned.endswith("```"):
                cleaned = cleaned.rsplit('```', 1)[0]
        result = json.loads(cleaned)
    except Exception:
        result = {"score": 0, "assignment_feedback": "No feedback available.", "total_weighted_score": total_weighted_score}
    return result 