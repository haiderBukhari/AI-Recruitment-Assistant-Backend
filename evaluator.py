import os
import re
import json
from typing_extensions import TypedDict
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import StateGraph, START, END

os.environ["GOOGLE_API_KEY"] = "AIzaSyBL6YSdMIc3FNAjSojv3Sn4ehcJonxnSik"

llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    temperature=0
)

class State(TypedDict):
    job_title: str
    job_description: str
    skill_condition: str
    company_info: str
    company_culture: str
    cv: str
    cover_letter: str
    experience_score: int
    experience_reason: str
    experience_facts: list[str]
    level_suggestion: str
    skill_score: int
    skill_reason: str
    culture_score: int
    culture_reason: str
    company_fit_score: int
    company_fit_reason: str
    total_weighted_score: float
    final_recommendation: str

def extract_score_reason_level_facts(text: str):
    score_match = re.search(r"Score:\s*(\d+)", text)
    reason_match = re.search(r"Reason:\s*(.+?)(?:\nLevel:|\nFacts:|$)", text, re.DOTALL)
    level_match = re.search(r"Level:\s*(\w+)", text)
    facts_match = re.findall(r"-\s*(.+)", text.split("Facts:")[-1]) if "Facts:" in text else []

    score = int(score_match.group(1)) if score_match else 0
    reason = reason_match.group(1).strip() if reason_match else "No reason provided."
    level = level_match.group(1).strip() if level_match else "N/A"
    facts = [fact.strip() for fact in facts_match][:5]

    return score, reason, level, facts

def score_experience(state: State) -> State:
    prompt = ChatPromptTemplate.from_template(
        """
        Evaluate the candidate's experience for the job title: {job_title},
        given this job description and skill conditions, ensure the candidate has the skills and experience to be a good fit for the job. When reviewing the CV, consider the following:
        - Relevance of past roles and responsibilities to the job requirements.
        - Breadth and depth of experience in key areas.
        - Evidence of progression and growth in previous positions.
        - Notable achievements or contributions in past roles.
        - Industry or domain expertise related to the position.
        - In Experience Facts, you can use bullet points to make it more concise and each bullet point should be a single fact not very long.
        Here is the job description:
        {job_description}

        here is the skill conditions:
        {skill_condition}

        CV:
        {cv}

        Cover Letter (optional):
        {cover_letter}

        Respond with:
        Score: <0-100>
        Reason: <1-2 lines>
        Level: <Junior/Mid/Senior>
        Facts:
        - fact 1
        - fact 2...
        """
    )
    response = (prompt | llm).invoke(state).content.strip()
    score, reason, level, facts = extract_score_reason_level_facts(response)

    return {
        **state,
        "experience_score": score,
        "experience_reason": reason,
        "level_suggestion": level,
        "experience_facts": facts
    }

def extract_skill_summary(text: str):
    score_match = re.search(r"Score:\s*(\d+)", text)
    present_skills = re.findall(r"Present Skills:\s*((?:- .+\n?)+)", text)
    missing_skills = re.findall(r"Missing/Weak Skills:\s*((?:- .+\n?)+)", text)
    readiness_match = re.search(r"Overall Readiness and Gaps:\s*(.+)", text, re.DOTALL)

    score = int(score_match.group(1)) if score_match else 0
    present = [s.strip('- ').strip() for s in present_skills[0].strip().split('\n')] if present_skills else []
    missing = [s.strip('- ').strip() for s in missing_skills[0].strip().split('\n')] if missing_skills else []
    readiness = readiness_match.group(1).strip() if readiness_match else "No summary provided."
    return score, present, missing, readiness

def score_skill_match(state: State) -> State:
    prompt = ChatPromptTemplate.from_template(
        """
        Based on the following skill conditions strictly specified by HR:\n{skill_condition}" if skill_condition else "Based solely on the job description below
        
        Job Description:
        {job_description}

        Evaluate the candidate's skill match by reviewing their CV and cover letter. Consider the following:
        - Relevant technical and soft skills listed in the CV (can be related, not necessarily exact keyword match).
        - Certifications, formal training, or education that support the job requirements.
        - Relevant projects or achievements demonstrating proficiency.
        - Recency and depth of skill usage.
        - Signs of continuous learning or professional development.

        Candidate CV:
        {cv}

        Cover Letter (if any):
        {cover_letter}

        Respond with:
        Score: <0–100>
        Skills Summary:
        Present Skills:
        - skill 1
        - skill 2
        Missing/Weak Skills:
        - skill 1
        - skill 2
        Overall Readiness and Gaps:
        <summary text>
        """
    )

    response = (prompt | llm).invoke(state).content.strip()
    score, present, missing, readiness = extract_skill_summary(response)

    skill_reason = (
        f"- **Present Skills:** {'; '.join(present) if present else 'None'}\n"
        f"- **Missing/Weak Skills:** {'; '.join(missing) if missing else 'None'}\n"
        f"- **Overall Readiness and Gaps:** {readiness}"
    )
    return {
        **state,
        "skill_score": score,
        "skill_reason": skill_reason
    }

def score_culture_fit(state: State) -> State:
    prompt = ChatPromptTemplate.from_template(
        """
        Evaluate the candidate's cultural fit by considering the company's working style, values, and beliefs. Review the candidate's professional background, approach to collaboration, and personal values to assess alignment with the company culture. Candidates who demonstrate strong teamwork and effective collaboration are likely to be a good cultural fit, while those who consistently prefer working independently may not align as well.
        
        here is the company info:
        {company_info}

        here is the company culture:
        {company_culture}

        here is the job description:
        {job_description}

        here is the CV:
        {cv}

        Candidate Cover Letter (optional if not present judge on CV):
        {cover_letter}

        Respond with:
        Score: <0–100>
        Reason: <Concise, 3-4 lines summary focusing only on the most relevant points for company fit>
        """
    )
    response = (prompt | llm).invoke(state).content.strip()
    score, reason, *_ = extract_score_reason_level_facts(response)
    return {
        **state,
        "culture_score": score,
        "culture_reason": reason
    }

def score_company_fit(state: State) -> State:
    prompt = ChatPromptTemplate.from_template(
        """
        Evaluate the candidate's alignment with the company's long-term vision and values by reviewing their CV. Consider the following:
        - Analyze career progression for evidence of growth, adaptability, and commitment to long-term goals.
        - Review achievements and projects for alignment with company values such as innovation, teamwork, leadership, or social responsibility.
        - Check for industry alignment by noting experience in similar industries or organizations with comparable missions.
        - Evaluate extracurricular involvement, such as volunteer work or professional memberships, that reflects the company's values or community engagement.
        - Look for consistency in the candidate's career choices and stated objectives with the company's vision and values.

        here is the company info:
        {company_info}

        here is the company culture:
        {company_culture}

        here is the job description:
        {job_description}

        here is the CV:
        {cv}

        Candidate Cover Letter (optional if not present judge on CV):
        {cover_letter}
        
        Respond with:
        Score: <0–100>
        Reason: <Concise, 3-4 lines summary focusing only on the most relevant points for company fit>
        """
    )
    response = (prompt | llm).invoke(state).content.strip()
    score, reason, *_ = extract_score_reason_level_facts(response)
    return {
        **state,
        "company_fit_score": score,
        "company_fit_reason": reason
    }

def final_decision(state: State) -> State:
    weighted_score = (
        state["experience_score"] * 0.5 +
        state["skill_score"] * 0.3 +
        state["culture_score"] * 0.1 +
        state["company_fit_score"] * 0.1
    )

    if weighted_score >= 75:
        recommendation = "Strong Match."
    elif weighted_score >= 55:
        recommendation = "Moderate Fit."
    else:
        recommendation = "Not a fit."

    return {
        **state,
        "final_recommendation": recommendation,
        "total_weighted_score": round(weighted_score, 2)
    }

workflow = StateGraph(State)
workflow.add_node("score_experience", score_experience)
workflow.add_node("score_skill_match", score_skill_match)
workflow.add_node("score_culture_fit", score_culture_fit)
workflow.add_node("score_company_fit", score_company_fit)
workflow.add_node("final_decision", final_decision)

workflow.add_edge(START, "score_experience")
workflow.add_edge("score_experience", "score_skill_match")
workflow.add_edge("score_skill_match", "score_culture_fit")
workflow.add_edge("score_culture_fit", "score_company_fit")
workflow.add_edge("score_company_fit", "final_decision")
workflow.add_edge("final_decision", END)

app = workflow.compile()

def run_full_evaluation(job_title, job_description, skill_condition, company_info, cv, cover_letter="", company_culture=""):
    input_state = {
        "job_title": job_title,
        "job_description": job_description,
        "skill_condition": skill_condition,
        "company_info": company_info,
        "cv": cv,
        "cover_letter": cover_letter,
        "company_culture": company_culture
    }
    return app.invoke(input_state)  # type: ignore 

