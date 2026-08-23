from pathlib import Path
import json

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from ranking import rank_vulnerabilities


# -------------------------
# Application
# -------------------------

app = FastAPI(
    title="RiskLens API",
    description="Personalised Vulnerability Intelligence",
    version="1.0.0"
)


# -------------------------
# CORS
# -------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------------
# Data paths
# -------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


# -------------------------
# Load vulnerability data
# -------------------------

vulnerabilities = pd.read_csv(
    DATA_DIR / "vulnerabilities.csv"
)


# -------------------------
# Load organisations
# -------------------------

with open(DATA_DIR / "profiles.json", "r") as file:
    profiles_data = json.load(file)

organizations = profiles_data["organizations"]


# -------------------------
# Root endpoint
# -------------------------

@app.get("/")
def root():
    return {
        "application": "RiskLens",
        "status": "online"
    }


# -------------------------
# Organisations endpoint
# -------------------------

@app.get("/api/organizations")
def get_organizations():

    return {
        "organizations": organizations
    }


# -------------------------
# Triage endpoint
# -------------------------

@app.post("/api/triage")
@app.get("/api/compare")
def compare_organizations():

    comparison = []

    for organization in organizations:

        results = rank_vulnerabilities(
            vulnerabilities,
            organization
        )

        comparison.append({
            "organization": {
                "id": organization["org_id"],
                "name": organization["name"],
                "sector": organization["sector"],
                "risk_appetite": organization["risk_appetite"]
            },
            "results": results
        })

    return {
        "comparison": comparison
    }
def triage(org_id: str):
    

    # Find organisation
    organization = next(
        (
            org
            for org in organizations
            if org["org_id"] == org_id
        ),
        None
    )

    if organization is None:
        raise HTTPException(
            status_code=404,
            detail="Organisation not found"
        )

    # Rank vulnerabilities
    results = rank_vulnerabilities(
        vulnerabilities,
        organization
    )

    return {
        "organization": {
            "id": organization["org_id"],
            "name": organization["name"],
            "sector": organization["sector"],
            "risk_appetite": organization["risk_appetite"]
        },
        "results": results
    }