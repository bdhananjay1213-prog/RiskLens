import math
import re

import pandas as pd


# ============================================
# DEFAULT CONFIGURATION
# ============================================

DEFAULT_WEIGHTS = {
    "cvss_weight": 0.40,
    "cisa_kev_weight": 0.35,
    "first_epss_weight": 0.25,
}


# ============================================
# DATA VALIDATION HELPERS
# ============================================

def parse_number(value, minimum, maximum, field_name):
    """
    Convert a value to a number and validate its range.

    Returns None when the value is missing.
    Raises ValueError when the value is invalid.
    """

    if value is None or pd.isna(value):
        return None

    if isinstance(value, str) and not value.strip():
        return None

    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(
            f"{field_name} must be a valid number."
        )

    if not math.isfinite(number):
        raise ValueError(
            f"{field_name} must be finite."
        )

    if not minimum <= number <= maximum:
        raise ValueError(
            f"{field_name} must be between "
            f"{minimum} and {maximum}."
        )

    return number


def parse_boolean(value):
    """
    Convert common boolean representations to True or False.

    Returns None when the value is missing or unknown.
    """

    if value is None or pd.isna(value):
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        if value == 1:
            return True

        if value == 0:
            return False

        return None

    value = str(value).strip().lower()

    if value in {"true", "yes", "1"}:
        return True

    if value in {"false", "no", "0"}:
        return False

    return None


def validate_cve_id(value):
    """
    Validate the basic structure of a CVE identifier.

    This checks the identifier's format, not whether
    the CVE exists in a trusted vulnerability database.
    """

    if value is None or pd.isna(value):
        return None

    value = str(value).strip().upper()

    pattern = r"^CVE-\d{4}-\d{4,}$"

    if not re.fullmatch(pattern, value):
        return None

    return value


# ============================================
# WEIGHT CONFIGURATION
# ============================================

def get_normalized_weights(organization=None):
    """
    Return normalised scoring weights.

    If an organisation is supplied, its weight modifiers
    override the defaults.

    The final weights always sum to 1.
    """

    weights = DEFAULT_WEIGHTS.copy()

    if organization:
        custom_weights = organization.get(
            "weight_modifiers",
            {}
        )

        for key in weights:
            if key in custom_weights:
                weights[key] = float(custom_weights[key])

    for key, value in weights.items():
        if not math.isfinite(value) or value < 0:
            raise ValueError(
                f"{key} must be a finite, "
                "non-negative number."
            )

    total_weight = sum(weights.values())

    if total_weight <= 0:
        raise ValueError(
            "At least one scoring weight must be positive."
        )

    return {
        key: value / total_weight
        for key, value in weights.items()
    }


# ============================================
# RISK SCORE CALCULATION
# ============================================

def calculate_score(vulnerability, organization=None):
    """
    Calculate a RiskLens vulnerability priority score.

    Signals:
    - CVSS: technical severity
    - KEV: known exploitation status
    - EPSS: estimated exploitation probability

    Missing signals are excluded from the calculation.
    The remaining weights are renormalised.

    Returns a score between 0 and 100.
    """

    weights = get_normalized_weights(organization)

    # ----------------------------------------
    # Extract and validate the signals
    # ----------------------------------------

    cvss = parse_number(
        vulnerability.get("cvss_base_score"),
        0,
        10,
        "CVSS"
    )

    kev = parse_boolean(
        vulnerability.get("cisa_kev")
    )

    epss = parse_number(
        vulnerability.get("first_epss"),
        0,
        1,
        "EPSS"
    )

    # CVSS is required for this scoring model.
    if cvss is None:
        raise ValueError(
            "A valid CVSS score is required."
        )

    # ----------------------------------------
    # Normalise CVSS to 0-1
    # ----------------------------------------

    cvss_normalized = cvss / 10

    # ----------------------------------------
    # Build available scoring signals
    # ----------------------------------------

    signals = {
        "cvss": (
            cvss_normalized,
            weights["cvss_weight"]
        )
    }

    if kev is not None:
        signals["kev"] = (
            1.0 if kev else 0.0,
            weights["cisa_kev_weight"]
        )

    if epss is not None:
        signals["epss"] = (
            epss,
            weights["first_epss_weight"]
        )

    # ----------------------------------------
    # Renormalise available weights
    # ----------------------------------------

    available_weight = sum(
        weight
        for _, weight in signals.values()
    )

    if available_weight <= 0:
        raise ValueError(
            "No usable scoring weights are available."
        )

    # ----------------------------------------
    # Calculate score contributions
    # ----------------------------------------

    contributions = {}

    for signal_name, (value, weight) in signals.items():

        contributions[signal_name] = (
            value
            * weight
            / available_weight
            * 100
        )

    total_score = sum(
        contributions.values()
    )

    return {
        "total": round(total_score, 2),
        "cvss": round(
            contributions.get("cvss", 0),
            2
        ),
        "kev": round(
            contributions.get("kev", 0),
            2
        ),
        "epss": round(
            contributions.get("epss", 0),
            2
        ),
        "available_signals": list(
            signals.keys()
        ),
    }


# ============================================
# PRIORITY CLASSIFICATION
# ============================================

def get_priority(score):
    """
    Classify a score between 0 and 100.
    """

    if score >= 80:
        return "URGENT"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


# ============================================
# RECOMMENDATION ENGINE
# ============================================

def generate_recommendation(vulnerability):
    """
    Generate a deterministic recommendation based
    on the available vulnerability evidence.

    This function does not execute exploits or
    independently verify whether a system is vulnerable.
    """

    cvss = parse_number(
        vulnerability.get("cvss_base_score"),
        0,
        10,
        "CVSS"
    )

    kev = parse_boolean(
        vulnerability.get("cisa_kev")
    )

    epss = parse_number(
        vulnerability.get("first_epss"),
        0,
        1,
        "EPSS"
    )

    if cvss is None:
        return {
            "action": "Review vulnerability data",
            "reason": (
                "A valid CVSS score is unavailable."
            ),
            "next_step": (
                "Retrieve the vulnerability details "
                "from a trusted source before prioritising."
            )
        }

    # ----------------------------------------
    # Known exploitation + critical severity
    # ----------------------------------------

    if kev is True and cvss >= 9:

        return {
            "action": "Urgent remediation",
            "reason": (
                "The vulnerability is listed as known "
                "exploited and has critical CVSS severity."
            ),
            "next_step": (
                "Verify the affected product and version, "
                "review vendor guidance, and prioritise "
                "the appropriate remediation."
            )
        }

    # ----------------------------------------
    # Known exploitation
    # ----------------------------------------

    if kev is True:

        return {
            "action": "Prioritise remediation",
            "reason": (
                "The vulnerability is listed in the "
                "Known Exploited Vulnerabilities catalogue."
            ),
            "next_step": (
                "Verify whether the affected product "
                "is deployed and prioritise remediation."
            )
        }

    # ----------------------------------------
    # High exploitation probability
    # ----------------------------------------

    if epss is not None and epss >= 0.70:

        return {
            "action": "Prioritise patch planning",
            "reason": (
                "The available EPSS value indicates "
                "a high estimated exploitation probability."
            ),
            "next_step": (
                "Verify exposure and schedule remediation "
                "with appropriate testing."
            )
        }

    # ----------------------------------------
    # Critical technical severity
    # ----------------------------------------

    if cvss >= 9:

        return {
            "action": "Review urgently",
            "reason": (
                "The vulnerability has critical "
                "technical severity."
            ),
            "next_step": (
                "Confirm whether the affected product "
                "is deployed and review vendor guidance."
            )
        }

    # ----------------------------------------
    # Missing exploitation intelligence
    # ----------------------------------------

    if kev is None or epss is None:

        return {
            "action": "Review available intelligence",
            "reason": (
                "One or more exploitation indicators "
                "are unavailable."
            ),
            "next_step": (
                "Retrieve the missing intelligence "
                "before making a more complete risk assessment."
            )
        }

    # ----------------------------------------
    # Standard remediation planning
    # ----------------------------------------

    return {
        "action": "Monitor and remediate",
        "reason": (
            "The available signals do not meet the "
            "engine's higher-priority conditions."
        ),
        "next_step": (
            "Track the vulnerability and include it "
            "in remediation planning."
        )
    }


# ============================================
# RANK VULNERABILITIES
# ============================================

def rank_vulnerabilities(
    vulnerabilities,
    organization=None,
    limit=5
):
    """
    Rank valid vulnerabilities from a DataFrame
    or a list of dictionaries.

    When organisation details are supplied:
    - Apply its scoring weights.
    - Filter by critical products if configured.

    Otherwise:
    - Analyse all valid records.
    - Use the default scoring weights.

    Invalid records are skipped.
    """

    if limit < 1:
        raise ValueError(
            "limit must be at least 1."
        )

    # ----------------------------------------
    # Support DataFrames and lists of records
    # ----------------------------------------

    if isinstance(vulnerabilities, pd.DataFrame):
        records = vulnerabilities.to_dict(
            orient="records"
        )

    elif isinstance(vulnerabilities, list):
        records = vulnerabilities

    else:
        raise TypeError(
            "vulnerabilities must be a DataFrame "
            "or a list of dictionaries."
        )

    # ----------------------------------------
    # Optional organisation configuration
    # ----------------------------------------

    critical_products = None

    if organization:
        configured_products = organization.get(
            "critical_products"
        )

        if configured_products is not None:
            critical_products = {
                str(product).strip().casefold()
                for product in configured_products
            }

    results = []

    # ----------------------------------------
    # Process uploaded records
    # ----------------------------------------

    for vulnerability in records:

        try:

            if not isinstance(vulnerability, dict):
                continue

            # Validate CVE identifier.
            cve_id = validate_cve_id(
                vulnerability.get("cve_id")
            )

            if cve_id is None:
                continue

            # Validate product name.
            product_value = vulnerability.get(
                "product_name"
            )

            if (
                product_value is None
                or pd.isna(product_value)
                or not str(product_value).strip()
            ):
                continue

            product = str(
                product_value
            ).strip()

            # Apply optional organisation filtering.
            if (
                critical_products is not None
                and product.casefold()
                not in critical_products
            ):
                continue

            # Calculate score.
            score_data = calculate_score(
                vulnerability,
                organization
            )

            total_score = score_data["total"]

            # Extract validated signals.
            cvss = parse_number(
                vulnerability.get("cvss_base_score"),
                0,
                10,
                "CVSS"
            )

            kev = parse_boolean(
                vulnerability.get("cisa_kev")
            )

            epss = parse_number(
                vulnerability.get("first_epss"),
                0,
                1,
                "EPSS"
            )

            # Generate recommendation.
            recommendation = generate_recommendation(
                vulnerability
            )

            # Build the result.
            result = {
                "cve_id": cve_id,
                "product": product,
                "score": total_score,
                "priority": get_priority(
                    total_score
                ),
                "cvss": cvss,
                "kev": kev,
                "epss": epss,
                "critical_product": (
                    critical_products is not None
                ),
                "score_breakdown": {
                    "cvss": score_data["cvss"],
                    "kev": score_data["kev"],
                    "epss": score_data["epss"],
                },
                "available_signals": (
                    score_data["available_signals"]
                ),
                "recommendation": recommendation,
            }

            results.append(result)

        except (ValueError, TypeError):
            # Ignore malformed records without
            # stopping the analysis of other records.
            continue

    # ----------------------------------------
    # Sort by score
    # ----------------------------------------

    results.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    # ----------------------------------------
    # Return the requested number of results
    # ----------------------------------------

    results = results[:limit]

    # ----------------------------------------
    # Add ranking numbers
    # ----------------------------------------

    for index, result in enumerate(
        results,
        start=1
    ):
        result["rank"] = index

    return results