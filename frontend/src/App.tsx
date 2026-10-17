import { useRef, useState, type DragEvent, type ChangeEvent } from "react";

const API_URL = "https://risklens-api-946g.onrender.com";
const MAX_FILE_SIZE = 10 * 1024 * 1024;

interface Vulnerability {
  rank: number;
  cve_id: string;
  product: string;
  score: number;
  priority: string;
  cvss: number;
  kev: boolean | null;
  epss: number | null;
  critical_product: boolean;
  available_signals: string[];
  score_breakdown: {
    cvss: number;
    kev: number;
    epss: number;
  };
  recommendation: {
    action: string;
    reason: string;
    next_step: string;
  };
}

interface UploadResponse {
  filename: string;
  records_received: number;
  records_ranked: number;
  results: Vulnerability[];
}

function App() {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [analysis, setAnalysis] = useState<UploadResponse | null>(null);
  const [uploading, setUploading] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  const results = analysis?.results ?? [];
  const urgentCount = results.filter((item) => item.priority === "URGENT").length;
  const highCount = results.filter((item) => item.priority === "HIGH").length;
  const kevCount = results.filter((item) => item.kev === true).length;
  const unknownKevCount = results.filter((item) => item.kev === null).length;
  const topScore = results.length > 0 ? results[0].score : 0;

  const validateSelectedFile = (file: File): boolean => {
    const extension = file.name.split(".").pop()?.toLowerCase();

    if (!extension || !["csv", "json"].includes(extension)) {
      setError("Unsupported file format. Please choose a CSV or JSON file.");
      setSuccessMessage("");
      return false;
    }

    if (file.size > MAX_FILE_SIZE) {
      setError("The maximum supported file size is 10 MB.");
      setSuccessMessage("");
      return false;
    }

    if (file.size === 0) {
      setError("The selected file is empty.");
      setSuccessMessage("");
      return false;
    }

    setSelectedFile(file);
    setError("");
    setSuccessMessage("");
    return true;
  };

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) validateSelectedFile(file);

    // Let the user select the same file again after removing it.
    event.target.value = "";
  };

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragActive(false);

    const file = event.dataTransfer.files?.[0];
    if (file) validateSelectedFile(file);
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setError("Please select a CSV or JSON vulnerability report first.");
      return;
    }

    setUploading(true);
    setError("");
    setSuccessMessage("");
    setAnalysis(null);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const formData = new FormData();
formData.append("file", selectedFile);

const response = await fetch(`${API_URL}/api/upload`, {
  method: "POST",
  body: formData,
});
      const payload = await response.json().catch(() => ({}));

      if (!response.ok) {
        const detail = payload?.detail;
        const message =
          typeof detail === "string"
            ? detail
            : detail?.message || `Upload failed with HTTP ${response.status}.`;
        throw new Error(message);
      }

      const result = payload as UploadResponse;

      if (!Array.isArray(result.results)) {
        throw new Error("The backend response did not contain a results array.");
      }

      setAnalysis(result);
      setSuccessMessage(
        `Analysis completed: ${result.records_ranked} of ${result.records_received} records were ranked.`
      );
    } catch (err) {
      console.error("RiskLens upload error:", err);
      setError(
        err instanceof Error
          ? err.message
          : "Unable to upload the report. Check that the RiskLens backend is running."
      );
    } finally {
      setUploading(false);
    }
  };

  const removeSelectedFile = () => {
    setSelectedFile(null);
    setError("");
    setSuccessMessage("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const priorityClass = (priority: string) => {
    switch (priority.toUpperCase()) {
      case "URGENT":
        return "urgent";
      case "HIGH":
        return "high";
      case "MEDIUM":
        return "medium";
      default:
        return "low";
    }
  };

  return (
    <div className="app">
      <style>{`
        .upload-panel {
          display: flex;
          flex-direction: column;
          align-items: stretch;
          gap: 18px;
          margin-bottom: 28px;
        }
        .upload-panel h2 { margin: 0 0 8px; font-size: 24px; }
        .upload-description { margin: 0; color: #8992a2; font-size: 14px; line-height: 1.65; }
        .upload-dropzone {
          border: 2px dashed #34445e;
          border-radius: 16px;
          padding: 34px 20px;
          text-align: center;
          background: rgba(15, 21, 32, 0.65);
          transition: border-color .2s ease, background .2s ease;
        }
        .upload-dropzone.drag-active {
          border-color: #6ea8ff;
          background: rgba(79, 125, 243, .12);
        }
        .upload-icon { font-size: 38px; margin-bottom: 10px; }
        .upload-dropzone h3 { margin: 0 0 8px; font-size: 17px; }
        .upload-dropzone p { color: #8b9ab2; font-size: 13px; margin: 0 0 14px; }
        .upload-actions { display: flex; flex-wrap: wrap; justify-content: center; gap: 10px; }
        .upload-select-button { display: inline-block; cursor: pointer; }
        .upload-hint { margin: 14px 0 0 !important; font-size: 11px !important; }
        .selected-file {
          display: flex; align-items: center; justify-content: space-between;
          flex-wrap: wrap; gap: 12px; padding: 14px;
          border: 1px solid #263247; border-radius: 10px; background: #111827;
        }
        .selected-file-name { overflow-wrap: anywhere; color: #dce2eb; font-size: 13px; }
        .selected-file-size { color: #8b9ab2; font-size: 12px; }
        .upload-submit-button:disabled { opacity: .55; cursor: not-allowed; }
        .upload-progress { color: #6ea8ff; font-size: 13px; }
        .upload-summary { padding: 16px; border: 1px solid #263247; border-radius: 12px; background: #111827; }
        .upload-summary p { margin: 8px 0 0; color: #a7b2c5; font-size: 13px; overflow-wrap: anywhere; }
        .success-box {
          margin: 18px 0; padding: 14px 18px; border: 1px solid #24533f;
          border-radius: 10px; background: #10241b; color: #79e0b0;
        }
        .empty-state { padding: 42px 24px; text-align: center; color: #7f8999; border: 1px solid #202631; border-radius: 15px; background: #0d1016; }
        .empty-state strong { display: block; color: #dce2eb; margin-bottom: 8px; }
        .empty-state p { margin: 0; font-size: 13px; line-height: 1.6; }
        .severity.medium { background: #253044; color: #8fb6ff; }
        .severity.low { background: #1d302b; color: #7edbb4; }
        .signals .kev { color: #ff6975; border-color: #4b252a; }
        .signal-unknown { border-color: #51462b !important; color: #d6bb78 !important; }
        .recommendation-reason { margin-top: 12px; color: #a2acbc; font-size: 12px; line-height: 1.6; }
        @media (max-width: 800px) {
          .upload-panel { align-items: stretch; }
          .upload-submit-button { width: 100%; }
        }
      `}</style>

      <header className="header">
        <div>
          <h1>🛡️ RiskLens</h1>
          <p>File-Driven Vulnerability Intelligence</p>
        </div>
        <div className="status">
          <span
            className="status-dot"
            style={uploading ? { background: "#6ea8ff", boxShadow: "0 0 12px #6ea8ff" } : undefined}
          />
          {uploading ? "Analysing report..." : "Ready for upload"}
        </div>
      </header>

      <main className="container">
        <section className="hero">
          <p className="eyebrow">SECURITY INTELLIGENCE</p>
          <h2>
            Understand the risks
            <br />
            that matter to you.
          </h2>
          <p className="hero-text">
            Upload a vulnerability report and RiskLens will validate its records,
            calculate risk scores, and prioritise findings using CVSS and the
            available exploitation intelligence.
          </p>
        </section>

        <section className="organisation-card upload-panel">
          <div>
            <p className="eyebrow">REPORT ANALYSIS</p>
            <h2>Upload a vulnerability report</h2>
            <p className="upload-description">
              Choose a CSV or JSON file containing vulnerability records. The
              current upload API expects <code>cve_id</code>, <code>product_name</code>,
              and <code>cvss_base_score</code>. KEV and EPSS values are optional.
            </p>
          </div>

          <div
            className={`upload-dropzone ${dragActive ? "drag-active" : ""}`}
            onDragOver={(event) => {
              event.preventDefault();
              setDragActive(true);
            }}
            onDragLeave={(event) => {
              event.preventDefault();
              setDragActive(false);
            }}
            onDrop={handleDrop}
            role="region"
            aria-label="Vulnerability report drop zone"
          >
            <div className="upload-icon">📂</div>
            <h3>Drag and drop your report here</h3>
            <p>Or browse your computer to select a file.</p>

            <div className="upload-actions">
              <button
                type="button"
                className="analyse-button upload-select-button"
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading}
              >
                Choose File
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".csv,.json, text/csv, application/json"
                hidden
                onChange={handleFileChange}
              />
            </div>
            <p className="upload-hint">CSV or JSON · Maximum file size: 10 MB</p>
          </div>

          {selectedFile && (
            <div className="selected-file">
              <div>
                <div className="selected-file-name">📄 {selectedFile.name}</div>
                <div className="selected-file-size">
                  {(selectedFile.size / 1024).toFixed(1)} KB
                </div>
              </div>
              <button
                type="button"
                className="secondary-button"
                onClick={removeSelectedFile}
                disabled={uploading}
              >
                Remove
              </button>
            </div>
          )}

          <button
            type="button"
            className="analyse-button upload-submit-button"
            onClick={handleUpload}
            disabled={!selectedFile || uploading}
          >
            {uploading ? "Analysing Report..." : "Upload & Analyse →"}
          </button>

          {uploading && (
            <p className="upload-progress">
              Sending the report to RiskLens and calculating vulnerability priorities...
            </p>
          )}

          {successMessage && <div className="success-box">✓ {successMessage}</div>}
          {error && <div className="error-box">⚠️ {error}</div>}

          {analysis && (
            <div className="upload-summary">
              <strong>Latest analysis</strong>
              <p>File: {analysis.filename}</p>
              <p>Records received: {analysis.records_received}</p>
              <p>Records ranked: {analysis.records_ranked}</p>
            </div>
          )}
        </section>

        <section className="stats">
          <div className="stat-card">
            <span>RECORDS RANKED</span>
            <strong>{analysis ? recordsText(analysis.records_ranked) : "—"}</strong>
            <p>Valid findings returned by the ranking engine</p>
          </div>
          <div className="stat-card">
            <span>URGENT</span>
            <strong>{analysis ? urgentCount : "—"}</strong>
            <p>Findings with an urgent score</p>
          </div>
          <div className="stat-card">
            <span>HIGH PRIORITY</span>
            <strong>{analysis ? highCount : "—"}</strong>
            <p>Findings requiring prioritised review</p>
          </div>
          <div className="stat-card highlight">
            <span>TOP RISK SCORE</span>
            <strong>{analysis ? topScore.toFixed(1) : "—"}</strong>
            <p>Highest calculated score out of 100</p>
          </div>
        </section>

        <section className="section-header">
          <div>
            <p className="eyebrow">PRIORITISED FINDINGS</p>
            <h2>Vulnerability Results</h2>
          </div>
          {analysis && (
            <button
              type="button"
              className="secondary-button"
              onClick={() => {
                setAnalysis(null);
                setSuccessMessage("");
              }}
            >
              Clear Results
            </button>
          )}
        </section>

        {analysis && (
          <p className="upload-description" style={{ marginBottom: 18 }}>
            Showing {results.length} ranked record(s) from <strong>{analysis.filename}</strong>.
            {unknownKevCount > 0 && ` KEV status is unknown for ${unknownKevCount} record(s).`}
            {kevCount > 0 && ` ${kevCount} record(s) are marked KEV in the supplied data.`}
          </p>
        )}

        <section className="risk-list">
          {uploading && <div className="loading">Analysing vulnerability records...</div>}

          {!uploading && !analysis && (
            <div className="empty-state">
              <strong>Your analysis will appear here</strong>
              <p>
                Upload a vulnerability report to see ranked findings, score
                breakdowns, and recommended next steps. No mock results are loaded.
              </p>
            </div>
          )}

          {!uploading && analysis && results.length === 0 && (
            <div className="empty-state">
              <strong>No records could be ranked</strong>
              <p>
                Check that your report contains valid CVE identifiers, product names,
                and CVSS scores between 0 and 10.
              </p>
            </div>
          )}

          {!uploading && results.map((risk) => (
            <article className="risk-card" key={`${risk.cve_id}-${risk.rank}`}>
              <div className="rank">#{risk.rank}</div>
              <div className="risk-content">
                <div className="risk-title">
                  <div>
                    <span className={`severity ${priorityClass(risk.priority)}`}>
                      {risk.priority}
                    </span>
                    <h3>{risk.cve_id}</h3>
                    <p>{risk.product}</p>
                  </div>
                  <div className="score">
                    <strong>{risk.score.toFixed(1)}</strong>
                    <span>/100</span>
                  </div>
                </div>

                <div className="signals">
                  <span>CVSS {risk.cvss.toFixed(1)}</span>
                  {risk.kev === true && <span className="kev">● KEV marked true</span>}
                  {risk.kev === false && <span>KEV: Not marked in supplied data</span>}
                  {risk.kev === null && <span className="signal-unknown">KEV: Unknown</span>}
                  <span>
                    EPSS {risk.epss === null ? "Unavailable" : risk.epss.toFixed(4)}
                  </span>
                </div>

                <div className="breakdown">
                  <strong>Why this ranked here</strong>
                  <div className="breakdown-row">
                    <span>CVSS contribution</span>
                    <span>+{risk.score_breakdown.cvss.toFixed(2)}</span>
                  </div>
                  <div className="breakdown-row">
                    <span>KEV contribution</span>
                    <span>+{risk.score_breakdown.kev.toFixed(2)}</span>
                  </div>
                  <div className="breakdown-row">
                    <span>EPSS contribution</span>
                    <span>+{risk.score_breakdown.epss.toFixed(2)}</span>
                  </div>
                  <div className="breakdown-total">
                    <span>Total RiskLens score</span>
                    <strong>{risk.score.toFixed(2)}</strong>
                  </div>
                  <p className="recommendation-reason">
                    Available signals: {risk.available_signals?.length
                      ? risk.available_signals.join(", ").toUpperCase()
                      : "Not specified"}
                  </p>
                </div>

                <div className="why">
                  <strong>Why does this matter?</strong>
                  <p>{risk.recommendation?.reason ?? "Review the available vulnerability data and validate it against trusted intelligence sources."}</p>
                </div>

                <div className="action">
                  <span>→</span>
                  <div>
                    <strong>{risk.recommendation?.action ?? "Review vulnerability"}</strong>
                    <p>{risk.recommendation?.next_step ?? "Verify the affected product and version, then consult vendor security guidance."}</p>
                  </div>
                </div>
              </div>
            </article>
          ))}
        </section>

        <p className="upload-description" style={{ marginTop: 24, fontSize: 12 }}>
          RiskLens scores are prioritisation aids, not proof that a product is vulnerable
          or that an attack has occurred. Verify supplied data and external intelligence
          before making remediation decisions.
        </p>
      </main>
    </div>
  );
}

function recordsText(value: number): string {
  return value.toLocaleString();
}

export default App;
