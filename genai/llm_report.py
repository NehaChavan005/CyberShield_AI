import google.generativeai as genai
import os

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

model = genai.GenerativeModel("gemini-1.5-flash")


def generate_llm_report(threat_info):

    attack = threat_info.get("attack_type", "unknown")
    risk = threat_info.get("risk_level", "unknown")
    explanation = threat_info.get("explanation", "")
    remediation = threat_info.get("remediation", "")

    prompt = f"""
You are a cybersecurity SOC analyst.

Analyze the following threat and produce a professional security incident report.

Attack Type: {attack}
Risk Level: {risk}

Explanation:
{explanation}

Recommended Remediation:
{remediation}

Write a short security incident report.
"""

    response = model.generate_content(prompt)

    return response.text