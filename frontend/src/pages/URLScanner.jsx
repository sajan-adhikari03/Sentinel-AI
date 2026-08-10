import { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

function URLScanner() {
  const navigate = useNavigate();

  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleScan = async (e) => {
    e.preventDefault();

    setError("");
    setResult(null);

    const trimmedUrl = url.trim();

    if (!trimmedUrl) {
      setError("Please enter a website URL.");
      return;
    }

    const token = sessionStorage.getItem("access_token");

    if (!token) {
      navigate("/login");
      return;
    }

    setLoading(true);

    try {
      const response = await axios.post(
        "http://127.0.0.1:5000/api/scan",
        {
          url: trimmedUrl,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (response.data.success) {
        setResult(response.data);
        setUrl("");
      } else {
        setError(
          response.data.error ||
            "Unable to analyze this URL."
        );
      }
    } catch (err) {
      if (err.response?.status === 401) {
        sessionStorage.removeItem("access_token");
        sessionStorage.removeItem("user");

        navigate("/login");
        return;
      }

      setError(
        err.response?.data?.error ||
          "Unable to connect to Sentinel server. Please make sure the backend is running."
      );
    } finally {
      setLoading(false);
    }
  };

  const getRiskClass = (score) => {
    if (score >= 70) {
      return "risk-high";
    }

    if (score >= 40) {
      return "risk-medium";
    }

    return "risk-low";
  };

  return (
    <div className="scanner-page">

      {/* Header */}
      <div className="scanner-page-header">

        <button
          type="button"
          className="back-dashboard"
          onClick={() => navigate("/dashboard")}
        >
          ← Dashboard
        </button>

        <span className="dashboard-eyebrow">
          SCAM DETECTION
        </span>

        <h1>
          URL Scanner
        </h1>

        <p>
          Analyze a suspicious website and understand
          its potential risk before you trust it.
        </p>

      </div>


      {/* Scanner */}
      <section className="url-scanner-card">

        <div className="scanner-card-icon">
          🔗
        </div>

        <h2>
          Check a Website URL
        </h2>

        <p>
          Enter the complete website address you want
          Sentinel to analyze.
        </p>

        <form
          className="url-scan-form"
          onSubmit={handleScan}
        >

          <div className="url-input-wrapper">

            <span>
              🔗
            </span>

            <input
              type="text"
              value={url}
              onChange={(e) =>
                setUrl(e.target.value)
              }
              placeholder="https://example.com"
              disabled={loading}
              autoComplete="off"
            />

          </div>

          <button
            type="submit"
            className="url-scan-button"
            disabled={loading}
          >
            {loading
              ? "Analyzing..."
              : "🔍 Scan URL"}
          </button>

        </form>


        {error && (
          <div className="scanner-message error">
            ✕ {error}
          </div>
        )}

      </section>


      {/* Result */}
      {result && (
        <section className="scan-result-card">

          <div className="result-header">

            <div>
              <span className="section-label">
                SENTINEL ANALYSIS
              </span>

              <h2>
                Scan Result
              </h2>
            </div>

            <span className="result-success">
              ✓ Analysis Complete
            </span>

          </div>


          {/* URL */}
          <div className="result-url">
            <span>
              Scanned URL
            </span>

            <strong>
              {result.url}
            </strong>
          </div>


          {/* Score */}
          <div className="risk-result">

            <div
              className={`risk-score ${getRiskClass(
                result.risk_score
              )}`}
            >
              <strong>
                {result.risk_score}
              </strong>

              <span>
                Risk Score
              </span>
            </div>


            <div className="risk-verdict">

              <span>
                Verdict
              </span>

              <strong>
                {result.verdict}
              </strong>

            </div>

          </div>


          {/* Reasons */}
          <div className="result-reasons">

            <h3>
              Why was this result given?
            </h3>

            {result.reasons?.length > 0 ? (
              <div className="reason-list">

                {result.reasons.map(
                  (reason, index) => (
                    <div
                      className="reason-item"
                      key={index}
                    >
                      <span>
                        ⚠️
                      </span>

                      <p>
                        {reason}
                      </p>
                    </div>
                  )
                )}

              </div>
            ) : (
              <p className="no-reasons">
                No additional indicators were returned.
              </p>
            )}

          </div>


          {/* Safety advice */}
          <div className="result-advice">

            <span>
              🛡️
            </span>

            <div>

              <strong>
                Safety Recommendation
              </strong>

              <p>
                Always verify suspicious websites independently
                before entering passwords, OTPs, payment details,
                or other sensitive information.
              </p>

            </div>

          </div>

        </section>
      )}

    </div>
  );
}

export default URLScanner;