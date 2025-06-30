import requests
import os
import json
import re
from typing_extensions import TypedDict
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import StateGraph, START, END
import logging
from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.DEBUG)

os.environ["GOOGLE_API_KEY"] = "AIzaSyBL6YSdMIc3FNAjSojv3Sn4ehcJonxnSik"

llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    temperature=0
)

JINA_API_KEY = os.getenv("JINA_API_KEY")
JINA_API_URL = "https://r.jina.ai/"
JINA_HEADERS = {
    "Accept": "application/json",
    "Authorization": f"Bearer {JINA_API_KEY}",
    "X-Retain-Images": "none",
    "X-With-Links-Summary": "all"
}

class CompanyState(TypedDict):
    website_url: str
    main_content: str
    about_content: str
    links: list[list[str]]
    company_description: str
    company_details: str
    company_culture: str
    company_values: list[str]
    linkedin: str
    twitter: str
    instagram: str
    facebook: str

def fetch_jina_json(url):
    response = requests.get(JINA_API_URL + url, headers=JINA_HEADERS)
    response.raise_for_status()
    return response.json()

def fetch_content(state: CompanyState) -> CompanyState:
    data = fetch_jina_json(state["website_url"])
    main_content = data["data"].get("content", "")
    links = data["data"].get("links", [])
    about_content = ""
    about_link = None
    for label, link in data["data"].get("links", []):
        if "/about" in link:
            about_link = link
            break
    if about_link:
        about_data = fetch_jina_json(about_link)
        about_content = about_data["data"].get("content", "")
    return {**state, "main_content": main_content, "about_content": about_content, "links": links}

# Improved Prompts
basic_info_prompt = ChatPromptTemplate.from_template(
    """
    From the following website content, extract:
    - Company Description (2-3 lines)
    - Company Details (4-5 lines, more in-depth)
    Respond in **valid JSON** with the exact keys:
    {{
      "company_description": "...",
      "company_details": "..."
    }}
    If not found, use empty strings. No extra text, no markdown, no explanation.
    Website Content:
    {content}
    """
)

culture_values_prompt = ChatPromptTemplate.from_template(
    """
    From the following website content (including the About page if present), extract:
    - Company Culture (3-4 lines; if not explicitly stated, infer from the company's mission, services, and language)
    - Core Values (as a JSON list of single words/phrases, e.g. ["Innovation", "Transparency", "Excellence", "Diversity", "Growth"])
    Respond in **valid JSON** with the exact keys:
    {{
      "company_culture": "...",
      "company_values": ["...", "..."]
    }}
    No extra text, no markdown, no explanation.
    Website Content:
    {content}
    """
)

def parse_json_response(response: str, required_keys: list[str], node_name: str):
    response = response.strip()
    if response.startswith("```json"):
        response = response.removeprefix("```json").removesuffix("```").strip()
    elif response.startswith("```"):
        response = response.removeprefix("```").removesuffix("```").strip()
    try:
        data = json.loads(response)
        if all(k in data for k in required_keys):
            return data
    except json.JSONDecodeError as e:
        logging.debug(f"[{node_name}] JSONDecodeError: {e}. Trying regex fallback.")
        json_part = re.search(r'\{.*\}', response, re.DOTALL)
        if json_part:
            try:
                data = json.loads(json_part.group())
                if all(k in data for k in required_keys):
                    return data
            except Exception as e2:
                logging.debug(f"[{node_name}] Regex JSON parse failed: {e2}")
    logging.debug(f"[{node_name}] Failed to parse JSON. Raw response:\n{response}")
    return None

def extract_basic_info(state: CompanyState) -> CompanyState:
    content = state["main_content"]
    response = (basic_info_prompt | llm).invoke({"content": content}).content.strip()
    logging.debug(f"[extract_basic_info] Raw response: {response}")
    data = parse_json_response(response, ["company_description", "company_details"], "extract_basic_info")
    if data:
        return {**state, "company_description": data.get("company_description", ""), "company_details": data.get("company_details", "")}
    return state

def extract_culture_values(state: CompanyState) -> CompanyState:
    combined_content = state["main_content"]
    if state["about_content"]:
        combined_content += "\n\n" + state["about_content"]
    response = (culture_values_prompt | llm).invoke({"content": combined_content}).content.strip()
    logging.debug(f"[extract_culture_values] Raw response: {response}")
    data = parse_json_response(response, ["company_culture", "company_values"], "extract_culture_values")
    if data:
        return {**state, "company_culture": data.get("company_culture", ""), "company_values": data.get("company_values", [])}
    return state

def extract_social_links(state: CompanyState) -> CompanyState:
    linkedin = ""
    twitter = ""
    instagram = ""
    facebook = ""

    for label, link in state.get("links", []):
        if not linkedin and "linkedin.com" in link:
            linkedin = link
        if not twitter and ("twitter.com" in link or "x.com" in link):
            twitter = link
        if not instagram and "instagram.com" in link:
            instagram = link
        if not facebook and "facebook.com" in link:
            facebook = link

    return {
        **state,
        "linkedin": linkedin,
        "twitter": twitter,
        "instagram": instagram,
        "facebook": facebook
    }

workflow = StateGraph(CompanyState)
workflow.add_node("fetch_content", fetch_content)
workflow.add_node("extract_basic_info", extract_basic_info)
workflow.add_node("extract_culture_values", extract_culture_values)
workflow.add_node("extract_social_links", extract_social_links)

workflow.add_edge(START, "fetch_content")
workflow.add_edge("fetch_content", "extract_basic_info")
workflow.add_edge("extract_basic_info", "extract_culture_values")
workflow.add_edge("extract_culture_values", "extract_social_links")
workflow.add_edge("extract_social_links", END)

app = workflow.compile()

def run_company_extraction(website_url: str):
    input_state = {
        "website_url": website_url,
        "main_content": "",
        "about_content": "",
        "links": [],
        "company_description": "",
        "company_details": "",
        "company_culture": "",
        "company_values": [],
        "linkedin": "",
        "twitter": "",
        "instagram": "",
        "facebook": ""
    }
    result = app.invoke(input_state)
    result.pop('main_content', None)
    result.pop('about_content', None)
    result.pop('links', None)
    return result