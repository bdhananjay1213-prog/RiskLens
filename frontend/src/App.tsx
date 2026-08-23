import { useEffect, useState } from "react";

const API_URL = "http://localhost:8000";

interface Organization {
  org_id: string;
  name: string;
  sector: string;
  risk_appetite: string;
  weight_modifiers: {
    cvss_weight: number;
    cisa_kev_weight: number;
    first_epss_weight: number;
  };
  critical_products: string[];
}

interface Vulnerability {
  rank: number;
  cve_id: string;
  product: string;
  score: number;
  priority: string;
  cvss: number;
  kev: boolean;
  epss: number;
  critical_product: boolean;

  score_breakdown: {
  cvss: number;
  kev: number;
  epss: number;
};
}

interface TriageResponse {
  organization: {
    id: string;
    name: string;
    sector: string;
    risk_appetite: string;
  };
  results: Vulnerability[];
}

function App() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [selectedOrg, setSelectedOrg] = useState("ORG-001");
  const [data, setData] = useState<TriageResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // --------------------------------
  // Load organisations
  // --------------------------------

  useEffect(() => {
    fetch(`${API_URL}/api/organizations`)
      .then((response) => {
        if (!response.ok) {
          throw new Error("Failed to load organisations");
        }

        return response.json();
      })
      .then((result) => {
        setOrganizations(result.organizations || []);
      })
      .catch((err) => {
        setError(err.message);
      });
  }, []);

  // --------------------------------
  // Run RiskLens analysis
  // --------------------------------

  const analyseRisk = async (orgId = selectedOrg) => {
  setLoading(true);
  setError("");

  try {
    const response = await fetch(
      `${API_URL}/api/triage?org_id=${encodeURIComponent(orgId)}`,
      {
        method: "POST",
        headers: {
          Accept: "application/json",
        },
      }
    );

    if (!response.ok) {
      throw new Error(
        `Risk analysis failed: HTTP ${response.status}`
      );
    }

    const result = await response.json();

    console.log("🔥 RiskLens TRIAGE RESPONSE:", result);

    // ---------------------------------------
    // Backend currently returns:
    //
    // {
    //   comparison: [
    //     {
    //       organization: {...},
    //       results: [...]
    //     },
    //     ...
    //   ]
    // }
    // ---------------------------------------

    if (Array.isArray(result.comparison)) {

      const selected = result.comparison.find(
        (item: any) =>
          item.organization?.id === orgId ||
          item.organization?.org_id === orgId
      );

      if (!selected) {
        throw new Error(
          `Organisation ${orgId} was not found in comparison data`
        );
      }

      setData({
        organization: {
          id:
            selected.organization.id ||
            selected.organization.org_id,

          name: selected.organization.name,

          sector:
            selected.organization.sector ||
            "Unknown",

          risk_appetite:
            selected.organization.risk_appetite ||
            "Unknown",
        },

        results: Array.isArray(selected.results)
          ? selected.results
          : [],
      });

    } else {

      // ---------------------------------------
      // Normal triage response fallback
      // ---------------------------------------

      if (!result.organization) {
        throw new Error(
          "Backend response is missing organization data"
        );
      }

      setData({
        organization: result.organization,
        results: Array.isArray(result.results)
          ? result.results
          : [],
      });
    }

  } catch (err) {

    console.error("❌ RiskLens error:", err);

    setError(
      err instanceof Error
        ? err.message
        : "Unable to connect to RiskLens backend"
    );

    setData(null);

  } finally {
    setLoading(false);
  }
};

  // --------------------------------
  // Automatically analyse first org
  // --------------------------------

  useEffect(() => {
    analyseRisk("ORG-001");
  }, []);

  // --------------------------------
  // Derived statistics
  // --------------------------------

  const results = data?.results || [];

  const urgentCount = results.filter(
    (item) => item.priority === "URGENT"
  ).length;

  const kevCount = results.filter(
    (item) => item.kev
  ).length;

  const topScore = results.length > 0
    ? results[0].score
    : 0;

  return (
    <div className="app">

      {/* HEADER */}
      <header className="header">

        <div>
          <h1>🛡️ RiskLens</h1>

          <p>
            Personalised Vulnerability Intelligence
          </p>
        </div>

        <div className="status">
          <span className="status-dot"></span>

          {loading ? "Analysing..." : "System Online"}
        </div>

      </header>


      <main className="container">

        {/* HERO */}

        <section className="hero">

          <div>

            <p className="eyebrow">
              SECURITY INTELLIGENCE
            </p>

            <h2>
              Understand the risks
              <br />
              that matter to you.
            </h2>

            <p className="hero-text">
              RiskLens analyses vulnerability data using your
              organisation's security context and prioritises
              the risks that deserve attention first.
            </p>

          </div>

        </section>


        {/* ORGANISATION SELECTOR */}

        <section className="organisation-card">

          <div>

            <label>
              ORGANISATION
            </label>

            <select
              value={selectedOrg}
              onChange={(event) => {
                const orgId = event.target.value;

                setSelectedOrg(orgId);
                analyseRisk(orgId);
              }}
              className="org-select"
            >

              {organizations.map((org) => (
                <option
                  key={org.org_id}
                  value={org.org_id}
                >
                  {org.name}
                </option>
              ))}

            </select>

            <h3>
              {data?.organization?.name || "Loading..."}
            </h3>

            <p>
              {data?.organization?.sector || "Loading sector"}
              {" · "}
              {data?.organization?.risk_appetite || "Loading risk appetite"}
            </p>

          </div>

          <button
            className="analyse-button"
            onClick={() => analyseRisk()}
            disabled={loading}
          >
            {loading ? "Analysing..." : "Analyse Risk →"}
          </button>

        </section>


        {/* ERROR */}

        {error && (
          <div className="error-box">
            ⚠️ {error}
          </div>
        )}


        {/* STATS */}

        <section className="stats">

          <div className="stat-card">

            <span>
              TOP RISKS
            </span>

            <strong>
              {results.length}
            </strong>

            <p>
              Prioritised vulnerabilities
            </p>

          </div>


          <div className="stat-card">

            <span>
              URGENT
            </span>

            <strong>
              {urgentCount}
            </strong>

            <p>
              Require immediate attention
            </p>

          </div>


          <div className="stat-card">

            <span>
              KEV DETECTED
            </span>

            <strong>
              {kevCount}
            </strong>

            <p>
              Known exploited vulnerabilities
            </p>

          </div>


          <div className="stat-card highlight">

            <span>
              TOP RISK SCORE
            </span>

            <strong>
              {topScore.toFixed(1)}
            </strong>

            <p>
              Highest prioritised risk
            </p>

          </div>

        </section>


        {/* TOP 5 HEADER */}

        <section className="section-header">

          <div>

            <p className="eyebrow">
              PRIORITISED THREATS
            </p>

            <h2>
              Top 5 Vulnerabilities
            </h2>

          </div>

          <button className="secondary-button">
            Compare Organisations
          </button>

        </section>


        {/* RISK LIST */}

        <section className="risk-list">

          {loading && (
            <div className="loading">
              Analysing vulnerabilities...
            </div>
          )}


          {!loading && results.map((risk) => (

            <div
              className="risk-card"
              key={risk.cve_id}
            >

              {/* RANK */}

              <div className="rank">
                #{risk.rank}
              </div>


              <div className="risk-content">

                {/* TITLE */}

                <div className="risk-title">

                  <div>

                    <span
                      className={`severity ${
                        risk.priority === "URGENT"
                          ? "urgent"
                          : "high"
                      }`}
                    >
                      {risk.priority}
                    </span>

                    <h3>
                      {risk.cve_id}
                    </h3>

                    <p>
                      {risk.product}
                    </p>

                  </div>


                  <div className="score">

                    <strong>
                      {risk.score.toFixed(1)}
                    </strong>

                    <span>
                      /100
                    </span>

                  </div>

                </div>


                {/* SIGNALS */}

                <div className="signals">

                  <span>
                    CVSS {risk.cvss.toFixed(1)}
                  </span>

                  {risk.kev && (
                    <span className="kev">
                      ● KEV Confirmed
                    </span>
                  )}

                  <span>
                    EPSS {risk.epss.toFixed(4)}
                  </span>

                  {risk.critical_product && (
                    <span>
                      ✓ Critical Product
                    </span>
                  )}

                </div>

                <div className="breakdown">

  <strong>Why this ranked here?</strong>

  <div className="breakdown-row">
    <span>CVSS</span>
    <span>+{risk.score_breakdown.cvss.toFixed(2)}</span>
  </div>

  <div className="breakdown-row">
    <span>KEV</span>
    <span>+{risk.score_breakdown.kev.toFixed(2)}</span>
  </div>

  <div className="breakdown-row">
    <span>EPSS</span>
    <span>+{risk.score_breakdown.epss.toFixed(2)}</span>
  </div>

  <div className="breakdown-total">
    <span>Total Priority Score</span>
    <strong>{risk.score.toFixed(2)}</strong>
  </div>

</div>


                {/* WHY */}

                <div className="why">

                  <strong>
                    Why does this matter?
                  </strong>

                  <p>

                    {risk.kev
                      ? "This vulnerability has a confirmed exploitation signal and "
                      : "This vulnerability has no confirmed exploitation signal, but "
                    }

                    it affects a critical product and has a technical severity of{" "}

                    <strong>
                      {risk.cvss.toFixed(1)}
                    </strong>

                    {" "}with an EPSS exploitation probability of{" "}

                    <strong>
                      {(risk.epss * 100).toFixed(1)}%
                    </strong>.

                  </p>

                </div>


                {/* NEXT ACTION */}

                <div className="action">

                  <span>
                    →
                  </span>

                  <div>

                    <strong>
                      Recommended next step
                    </strong>

                    <p>
                      Review the affected product and
                      applicable vendor security guidance.
                    </p>

                  </div>

                </div>

              </div>

            </div>

          ))}


          {!loading && results.length === 0 && !error && (

            <div className="loading">
              No relevant vulnerabilities found.
            </div>

          )}

        </section>

      </main>

    </div>
  );
}

export default App;