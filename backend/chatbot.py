import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise RuntimeError("GEMINI_API_KEY is not configured")

client = genai.Client(api_key=API_KEY)


def ask_risklens(question: str, context: dict) -> str:
    prompt = f"""
You are RiskLens Security Copilot.

You help explain vulnerability prioritisation results.

IMPORTANT RULES:
- Use ONLY the RiskLens context supplied below.
- Do not invent CVEs, scores, products, vulnerabilities, or exploitation facts.
- Do not claim that a system is definitely vulnerable or secure.
- Give defensive, safe cybersecurity guidance.
- If the supplied context does not contain enough information, say so.
- Explain CVSS, KEV and EPSS when useful.
- Distinguish the RiskLens score from EPSS probability.
- Keep answers concise and useful for a security analyst.

CURRENT RISKLENS CONTEXT:

{context}

USER QUESTION:

{question}

Answer as RiskLens Security Copilot.
"""

    response = client.models.generate_content(
        model="gemini-3.6-flash",
        contents=prompt,
    )

    return response.text