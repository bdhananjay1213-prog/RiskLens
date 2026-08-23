def calculate_score(vulnerability, organization):
    """
    Calculate the personalised RiskLens score.

    Signals:
    - CVSS  -> technical severity
    - KEV   -> confirmed exploitation
    - EPSS  -> exploitation probability

    The organisation's profile determines how much
    each signal contributes to the final score.
    """

    weights = organization["weight_modifiers"]

    # --------------------------------
    # CVSS
    # --------------------------------
    # CVSS is 0-10, normalize to 0-1
    cvss = float(vulnerability["cvss_base_score"]) / 10

    # --------------------------------
    # KEV
    # --------------------------------
    # True = 1
    # False = 0
    kev = (
        1
        if str(vulnerability["cisa_kev"]).lower() == "true"
        else 0
    )

    # --------------------------------
    # EPSS
    # --------------------------------
    # EPSS is already between 0 and 1
    epss = float(vulnerability["first_epss"])

    # --------------------------------
    # Individual contributions
    # --------------------------------

    cvss_contribution = (
        cvss
        * weights["cvss_weight"]
        * 100
    )

    kev_contribution = (
        kev
        * weights["cisa_kev_weight"]
        * 100
    )

    epss_contribution = (
        epss
        * weights["first_epss_weight"]
        * 100
    )

    # --------------------------------
    # Final score
    # --------------------------------

    total_score = (
        cvss_contribution
        + kev_contribution
        + epss_contribution
    )

    return {
        "total": total_score,
        "cvss": cvss_contribution,
        "kev": kev_contribution,
        "epss": epss_contribution
    }


# --------------------------------
# Priority classification
# --------------------------------

def get_priority(score):
    """
    Convert a 0-1 score into a human-readable priority.
    """

    if score >= 0.80:
        return "URGENT"

    elif score >= 0.60:
        return "HIGH"

    elif score >= 0.40:
        return "MEDIUM"

    else:
        return "LOW"


# --------------------------------
# Rank vulnerabilities
# --------------------------------

def rank_vulnerabilities(vulnerabilities, organization):
    """
    Match vulnerabilities against the organisation's
    critical products and return the Top 5 risks.
    """

    critical_products = organization["critical_products"]

    results = []

    # --------------------------------
    # Process every vulnerability
    # --------------------------------

    for _, vulnerability in vulnerabilities.iterrows():

        product = str(
            vulnerability["product_name"]
        ).strip()

        # --------------------------------
        # Product relevance
        # --------------------------------

        if product not in critical_products:
            continue

        # --------------------------------
        # Calculate personalised score
        # --------------------------------

        score_data = calculate_score(
            vulnerability,
            organization
        )

        total_score = score_data["total"]

        # --------------------------------
        # Create result
        # --------------------------------

        result = {
            "cve_id": str(
                vulnerability["cve_id"]
            ),

            "product": product,

            "score": round(
                total_score,
                2
            ),

            "priority": get_priority(
                total_score / 100
            ),

            "cvss": float(
                vulnerability["cvss_base_score"]
            ),

            "kev": (
                str(
                    vulnerability["cisa_kev"]
                ).lower()
                == "true"
            ),

            "epss": float(
                vulnerability["first_epss"]
            ),

            "critical_product": True,

            # --------------------------------
            # Explainable score
            # --------------------------------

            "score_breakdown": {
                "cvss": round(
                    score_data["cvss"],
                    2
                ),

                "kev": round(
                    score_data["kev"],
                    2
                ),

                "epss": round(
                    score_data["epss"],
                    2
                )
            }
        }

        results.append(result)

    # --------------------------------
    # Sort highest priority first
    # --------------------------------

    results.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    # --------------------------------
    # Keep Top 5
    # --------------------------------

    results = results[:5]

    # --------------------------------
    # Add rank
    # --------------------------------

    for index, result in enumerate(
        results,
        start=1
    ):
        result["rank"] = index

    return results