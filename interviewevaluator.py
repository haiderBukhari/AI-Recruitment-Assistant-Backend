import os
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI

os.environ["GOOGLE_API_KEY"] = "AIzaSyBL6YSdMIc3FNAjSojv3Sn4ehcJonxnSik"

llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    temperature=0
)

def evaluate_interview_performance(stage, details, total_weighted_score, previous_scores, job_title, job_description, skill_condition):
    import json
    details_str = json.dumps(details, indent=2)
    prev_scores_str = ', '.join(str(s) for s in previous_scores) if previous_scores else 'None'
    prompt = ChatPromptTemplate.from_template(
        f"""
        You are an expert interviewer. Based on the following interview stage and the provided interview details, evaluate the candidate's performance.
        
        Interview Stage: {{stage}}
        Job Title: {{job_title}}
        Job Description: {{job_description}}
        Skill Condition: {{skill_condition}}
        Interview Details (JSON):
        {{details_str}}
        
        The candidate's current overall score is represented by Total Weighted Score: {{total_weighted_score}} (out of 100). This score can go up or down slightly based on your evaluation of this interview, but should not vary too much from the current value. Only increase or decrease the score a little according to the candidate's performance and recruiter feedback. If you change the score, provide a clear reason for the change in the suggestion.
        Previous Interview Scores: {{prev_scores_str}}
        
        Please provide:
        - An updated score from 0 to 100 for this interview (key: 'score')
        - A brief suggestion (1-2 lines, key: 'suggestion')
        - Four ratings out of 5 for the following categories:
          - Overall Rating (key: 'overall_rating')
          - Professionalism (key: 'professionalism')
          - Communication (key: 'communication')
          - Job Related Skill (key: 'job_related_skill')
        
        Respond in the following JSON format:
        {{{{
            "score": <number>,
            "suggestion": "...",
            "overall_rating": <number>,
            "professionalism": <number>,
            "communication": <number>,
            "job_related_skill": <number>
        }}}}
        """
    )
    response = (prompt | llm).invoke({
        "stage": stage,
        "details_str": details_str,
        "total_weighted_score": total_weighted_score,
        "prev_scores_str": prev_scores_str,
        "job_title": job_title,
        "job_description": job_description,
        "skill_condition": skill_condition
    }).content.strip()
    try:
        cleaned = response.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split('\n', 1)[-1]
            if cleaned.endswith("```"):
                cleaned = cleaned.rsplit('```', 1)[0]
        result = json.loads(cleaned)
    except Exception:
        result = {"score": 0, "suggestion": "No suggestion available.", "overall_rating": 0, "professionalism": 0, "communication": 0, "job_related_skill": 0}
    return result 