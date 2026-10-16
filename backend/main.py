
from pathlib import Path
import json
import math

import pandas as pd

from fastapi import (
    FastAPI,
    HTTPException,
    UploadFile,
    File,
)

from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from chatbot import ask_risklens
from ranking import rank_vulnerabilities


# ============================================
# CONFIGURATION
# ============================================

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

ALLOWED_EXTENSIONS = {".csv", ".json"}

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


# ============================================
# REQUEST MODELS
# ============================================

class ChatRequest(BaseModel):
    question: str
    org_id: str


# ============================================
# APPLICATION
# ============================================

app = FastAPI(
    title="RiskLens API",
    description="File-Driven Vulnerability Intelligence",
    version="1.1.0",
)


# ============================================
# CORS
# ============================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173",
                  "https://risk1lens.netlify.app"
                  ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================
# OPTIONAL ORGANISATION CONFIGURATION
# ============================================

profiles_file = DATA_DIR / "profiles.json"

if profiles_file.exists():
    with open(profiles_file, "r", encoding="utf-8") as file:
        profiles_data = json.load(file)

    organizations = profiles_data.get("organizations", [])
else:
    organizations = []


# ============================================
# IN-MEMORY ANALYSIS CACHE
# ============================================

# Temporary storage for the latest uploaded analysis.
# This is suitable for local development only.
# It is not a persistent database.

latest_analysis = None


# ============================================
# ROOT ENDPOINT
# ============================================

@app.get("/")
def root():
    return {
        "application": "RiskLens",
        "status": "online",
        "mode": "file-driven vulnerability analysis",
    }


# ============================================
# HEALTH ENDPOINT
# ============================================

@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "upload_enabled": True,
        "supported_formats": ["CSV", "JSON"],
        "max_file_size_mb": 10,
    }


# ============================================
# FILE UPLOAD ENDPOINT
# ============================================

@app.post("/api/upload")
async def upload_vulnerability_report(
    file: UploadFile = File(...)
):
    """
    Receive a vulnerability report, validate it,
    rank its records, and return the analysis.

    Accepted formats:
    - CSV
    - JSON

    Expected vulnerability fields:
    - cve_id
    - product_name
    - cvss_base_score

    Optional fields:
    - cisa_kev
    - first_epss
    """

    global latest_analysis

    # ----------------------------------------
    # Validate filename
    # ----------------------------------------

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="A filename is required.",
        )

    extension = Path(file.filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail="Unsupported file format. Upload CSV or JSON.",
        )

    # ----------------------------------------
    # Read with a strict size limit
    # ----------------------------------------

    content = await file.read(MAX_FILE_SIZE + 1)

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File exceeds the 10 MB limit.",
        )

    if not content:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file is empty.",
        )

    # ----------------------------------------
    # Parse uploaded content
    # ----------------------------------------

    try:

        if extension == ".csv":

            from io import BytesIO

            vulnerabilities = pd.read_csv(
                BytesIO(content),
                dtype=str,
                keep_default_na=False,
                on_bad_lines="error",
            )

        else:

            payload = json.loads(
                content.decode("utf-8-sig")
            )

            if isinstance(payload, dict):
                payload = payload.get(
                    "vulnerabilities",
                    [payload],
                )

            if not isinstance(payload, list):
                raise ValueError(
                    "JSON must contain a list of vulnerability records."
                )

            if not all(
                isinstance(record, dict)
                for record in payload
            ):
                raise ValueError(
                    "Every JSON record must be an object."
                )

            vulnerabilities = pd.DataFrame(payload)

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        pd.errors.ParserError,
        ValueError,
    ) as exc:

        raise HTTPException(
            status_code=400,
            detail=f"Unable to parse uploaded file: {exc}",
        ) from exc

    # ----------------------------------------
    # Check required fields
    # ----------------------------------------

    required_fields = {
        "cve_id",
        "product_name",
        "cvss_base_score",
    }

    missing_fields = required_fields - set(
        vulnerabilities.columns
    )

    if missing_fields:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Required vulnerability fields are missing.",
                "missing_fields": sorted(missing_fields),
                "required_fields": sorted(required_fields),
            },
        )

    if vulnerabilities.empty:
        raise HTTPException(
            status_code=422,
            detail="The uploaded file contains no vulnerability records.",
        )

    # ----------------------------------------
    # Limit the number of records
    # ----------------------------------------

    if len(vulnerabilities) > 20000:
        raise HTTPException(
            status_code=413,
            detail="A maximum of 20,000 records is supported.",
        )

    # ----------------------------------------
    # Run the ranking engine
    # ----------------------------------------

    try:

        ranked_results = rank_vulnerabilities(
            vulnerabilities,
            organization=None,
            limit=20000,
        )

    except (ValueError, TypeError) as exc:

        raise HTTPException(
            status_code=422,
            detail=f"Unable to analyse vulnerability data: {exc}",
        ) from exc

    # ----------------------------------------
    # Store latest analysis in memory
    # ----------------------------------------

    latest_analysis = {
        "filename": Path(file.filename).name,
        "records_received": len(vulnerabilities),
        "records_ranked": len(ranked_results),
        "results": ranked_results,
    }

    # ----------------------------------------
    # Return analysis
    # ----------------------------------------

    return {
        "filename": latest_analysis["filename"],
        "records_received": len(vulnerabilities),
        "records_ranked": len(ranked_results),
        "results": ranked_results,
    }


# ============================================
# LATEST ANALYSIS ENDPOINT
# ============================================

@app.get("/api/analysis/latest")
def get_latest_analysis():

    if latest_analysis is None:
        raise HTTPException(
            status_code=404,
            detail="No vulnerability report has been uploaded yet.",
        )

    return latest_analysis


# ============================================
# ORGANISATIONS ENDPOINT
# ============================================

@app.get("/api/organizations")
def get_organizations():

    return {
        "organizations": organizations,
    }


# ============================================
# COMPARE ORGANISATIONS
# ============================================

@app.get("/api/compare")
def compare_organizations():

    if latest_analysis is None:
        raise HTTPException(
            status_code=409,
            detail="Upload a vulnerability report before comparing organisations.",
        )

    comparison = []

    for organization in organizations:

        results = rank_vulnerabilities(
            pd.DataFrame(
                latest_analysis["results"]
            ),
            organization,
        )

        comparison.append({
            "organization": {
                "id": organization["org_id"],
                "name": organization["name"],
                "sector": organization["sector"],
                "risk_appetite": organization["risk_appetite"],
            },
            "results": results,
        })

    return {
        "comparison": comparison,
    }


# ============================================
# TRIAGE ORGANISATION
# ============================================

@app.post("/api/triage")
def triage(org_id: str):

    if latest_analysis is None:
        raise HTTPException(
            status_code=409,
            detail="Upload a vulnerability report before running triage.",
        )

    organization = next(
        (
            org
            for org in organizations
            if org["org_id"] == org_id
        ),
        None,
    )

    if organization is None:
        raise HTTPException(
            status_code=404,
            detail="Organisation not found.",
        )

    results = rank_vulnerabilities(
        pd.DataFrame(
            latest_analysis["results"]
        ),
        organization,
    )

    return {
        "organization": {
            "id": organization["org_id"],
            "name": organization["name"],
            "sector": organization["sector"],
            "risk_appetite": organization["risk_appetite"],
        },
        "results": results,
    }


# ============================================
# AI SECURITY COPILOT
# ============================================

@app.post("/api/chat")
def chat_with_risklens(request: ChatRequest):

    if latest_analysis is None:
        raise HTTPException(
            status_code=409,
            detail="Upload a vulnerability report before using Security Copilot.",
        )

    organization = next(
        (
            org
            for org in organizations
            if org["org_id"] == request.org_id
        ),
        None,
    )

    if organization is None:
        raise HTTPException(
            status_code=404,
            detail="Organisation not found.",
        )

    results = rank_vulnerabilities(
        pd.DataFrame(
            latest_analysis["results"]
        ),
        organization,
    )

    context = {
        "organization": {
            "id": organization["org_id"],
            "name": organization["name"],
            "sector": organization["sector"],
            "risk_appetite": organization["risk_appetite"],
        },
        "uploaded_filename": latest_analysis["filename"],
        "records_received": latest_analysis["records_received"],
        "top_5_vulnerabilities": results[:5],
    }

    answer = ask_risklens(
        request.question,
        context,
    )

    return {
        "organization": organization["name"],
        "answer": answer,
    }
