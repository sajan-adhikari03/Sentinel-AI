import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

const API_BASE_URL = "http://127.0.0.1:5000";

function ScanHistory() {
  const navigate = useNavigate();

  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("ALL");
  const [selectedScan, setSelectedScan] = useState(null);

  // ============================================================
  // AUTH TOKEN
  // ============================================================

  const getToken = () => {
    return sessionStorage.getItem("access_token");
  };

  // ============================================================
  // LOAD USER HISTORY
  // ============================================================

  const loadHistory = async () => {
    try {
      setLoading(true);
      setError("");

      const token = getToken();

      if (!token) {
        navigate("/login");
        return;
      }

      const response = await fetch(
        `${API_BASE_URL}/api/history`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      if (response.status === 401) {
        sessionStorage.removeItem("access_token");
        sessionStorage.removeItem("user");
        navigate("/login");
        return;
      }

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data?.error ||
            data?.msg ||
            "Failed to load scan history."
        );
      }

      const history = Array.isArray(data)
        ? data
        : data.scans || data.history || [];

      setScans(history);
    } catch (err) {
      console.error("History error:", err);

      setError(
        err.message || "Unable to load scan history."
      );
    } finally {
      setLoading(false);
    }
  };

  // ============================================================
  // INITIAL LOAD
  // ============================================================

  useEffect(() => {
    loadHistory();
  }, []);

  // ============================================================
  // STATUS
  // ============================================================

  const getStatus = (scan) => {
    const verdict = String(
      scan?.verdict || ""
    ).toUpperCase();

    if (verdict === "SAFE") {
      return "SAFE";
    }

    if (verdict === "SUSPICIOUS") {
      return "SUSPICIOUS";
    }

    if (
      verdict === "HIGH RISK" ||
      verdict === "HIGH_RISK"
    ) {
      return "HIGH RISK";
    }

    if (verdict === "CRITICAL") {
      return "CRITICAL";
    }

    const score = Number(
      scan?.risk_score || 0
    );

    if (score >= 80) {
      return "CRITICAL";
    }

    if (score >= 60) {
      return "HIGH RISK";
    }

    if (score >= 30) {
      return "SUSPICIOUS";
    }

    return "SAFE";
  };

  // ============================================================
  // STATUS CSS
  // ============================================================

  const getStatusClass = (status) => {
    switch (status) {
      case "SAFE":
        return "history-status safe";

      case "SUSPICIOUS":
        return "history-status suspicious";

      case "HIGH RISK":
        return "history-status high";

      case "CRITICAL":
        return "history-status critical";

      default:
        return "history-status";
    }
  };

  // ============================================================
  // FILTER + SEARCH
  // ============================================================

  const filteredScans = useMemo(() => {
    const query = search.trim().toLowerCase();

    return scans.filter((scan) => {
      const status = getStatus(scan);

      const matchesFilter =
        filter === "ALL" ||
        status === filter;

      const url = String(
        scan?.url || ""
      ).toLowerCase();

      const matchesSearch =
        !query ||
        url.includes(query) ||
        status.toLowerCase().includes(query);

      return (
        matchesFilter &&
        matchesSearch
      );
    });
  }, [scans, search, filter]);

  // ============================================================
  // DATE
  // ============================================================

  const formatDate = (dateValue) => {
    if (!dateValue) {
      return "Unknown date";
    }

    const date = new Date(dateValue);

    if (Number.isNaN(date.getTime())) {
      return String(dateValue);
    }

    return date.toLocaleString();
  };

  // ============================================================
  // NUMBER FORMAT
  // ============================================================

  const formatNumber = (value, fallback = 0) => {
    const number = Number(value);

    if (Number.isNaN(number)) {
      return fallback;
    }

    return number;
  };

  // ============================================================
  // ML PROBABILITY
  // ============================================================

  const getMLProbability = (scan) => {
    if (
      scan?.ml_probability !== undefined &&
      scan?.ml_probability !== null
    ) {
      return formatNumber(
        scan.ml_probability
      );
    }

    if (
      scan?.phishing_probability !== undefined &&
      scan?.phishing_probability !== null
    ) {
      return formatNumber(
        scan.phishing_probability
      );
    }

    return null;
  };

  // ============================================================
  // PARSE REASONS
  // ============================================================

  const parseReasons = (scan) => {
    if (!scan?.reasons) {
      return [];
    }

    if (Array.isArray(scan.reasons)) {
      return scan.reasons;
    }

    if (typeof scan.reasons === "string") {
      try {
        const parsed = JSON.parse(
          scan.reasons
        );

        if (Array.isArray(parsed)) {
          return parsed;
        }

        return [scan.reasons];
      } catch {
        return [scan.reasons];
      }
    }

    return [];
  };

  // ============================================================
  // DELETE
  // ============================================================

  const handleDelete = async (scanId) => {
    const confirmed = window.confirm(
      "Are you sure you want to delete this scan?"
    );

    if (!confirmed) {
      return;
    }

    try {
      const token = getToken();

      if (!token) {
        navigate("/login");
        return;
      }

      const response = await fetch(
        `${API_BASE_URL}/api/history/${scanId}`,
        {
          method: "DELETE",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      const data = await response.json();

      if (response.status === 401) {
        sessionStorage.removeItem("access_token");
        sessionStorage.removeItem("user");
        navigate("/login");
        return;
      }

      if (!response.ok) {
        throw new Error(
          data?.error ||
            data?.msg ||
            "Failed to delete scan."
        );
      }

      setScans((previous) =>
        previous.filter(
          (scan) =>
            scan.id !== scanId
        )
      );

      if (
        selectedScan &&
        selectedScan.id === scanId
      ) {
        setSelectedScan(null);
      }
    } catch (err) {
      console.error(
        "Delete error:",
        err
      );

      window.alert(
        err.message ||
          "Unable to delete this scan."
      );
    }
  };

  // ============================================================
  // CLEAR FILTERS
  // ============================================================

  const clearFilters = () => {
    setSearch("");
    setFilter("ALL");
  };

  // ============================================================
  // RENDER
  // ============================================================

  return (
    <div className="dashboard-page">

      <main className="dashboard-content history-page">

        {/* ====================================================
            PAGE HEADER
        ==================================================== */}

        <section className="dashboard-welcome history-welcome">

          <div>

            <span className="dashboard-eyebrow">
              SECURITY ACTIVITY
            </span>

            <h2>
              Scan History
            </h2>

            <p>
              Review the URLs you have analyzed with
              Sentinel.
            </p>

          </div>

          <button
            type="button"
            className="history-scan-button"
            onClick={() =>
              navigate(
                "/dashboard/url-scanner"
              )
            }
          >
            🔍 Scan New URL
          </button>

        </section>


        {/* ====================================================
            STATISTICS
        ==================================================== */}

        <section className="dashboard-stats">

          {/* TOTAL */}

          <div className="stat-card">

            <div className="stat-icon">
              🔍
            </div>

            <div>

              <span>
                Total Scans
              </span>

              <strong>
                {scans.length}
              </strong>

            </div>

          </div>


          {/* SAFE */}

          <div className="stat-card">

            <div className="stat-icon">
              🟢
            </div>

            <div>

              <span>
                Safe
              </span>

              <strong>
                {
                  scans.filter(
                    (scan) =>
                      getStatus(scan) ===
                      "SAFE"
                  ).length
                }
              </strong>

            </div>

          </div>


          {/* SUSPICIOUS */}

          <div className="stat-card">

            <div className="stat-icon">
              🟡
            </div>

            <div>

              <span>
                Suspicious
              </span>

              <strong>
                {
                  scans.filter(
                    (scan) =>
                      getStatus(scan) ===
                      "SUSPICIOUS"
                  ).length
                }
              </strong>

            </div>

          </div>


          {/* HIGH RISK */}

          <div className="stat-card">

            <div className="stat-icon">
              🔴
            </div>

            <div>

              <span>
                High Risk
              </span>

              <strong>
                {
                  scans.filter(
                    (scan) =>
                      getStatus(scan) ===
                        "HIGH RISK" ||
                      getStatus(scan) ===
                        "CRITICAL"
                  ).length
                }
              </strong>

            </div>

          </div>

        </section>


        {/* ====================================================
            HISTORY PANEL
        ==================================================== */}

        <section className="recent-scans history-panel">

          <div className="section-header">

            <div>

              <span className="section-label">
                ACTIVITY LOG
              </span>

              <h3>
                Your Scans
              </h3>

              <p>
                Only scans belonging to your account
                are displayed here.
              </p>

            </div>

          </div>


          {/* ==================================================
              SEARCH + FILTER
          ================================================== */}

          <div className="history-controls">

            <div className="history-search">

              <span>
                🔎
              </span>

              <input
                type="text"
                value={search}
                onChange={(event) =>
                  setSearch(
                    event.target.value
                  )
                }
                placeholder="Search scanned URLs..."
              />

            </div>


            <select
              value={filter}
              onChange={(event) =>
                setFilter(
                  event.target.value
                )
              }
              className="history-filter"
            >

              <option value="ALL">
                All Status
              </option>

              <option value="SAFE">
                Safe
              </option>

              <option value="SUSPICIOUS">
                Suspicious
              </option>

              <option value="HIGH RISK">
                High Risk
              </option>

              <option value="CRITICAL">
                Critical
              </option>

            </select>


            {(search || filter !== "ALL") && (

              <button
                type="button"
                className="history-clear"
                onClick={clearFilters}
              >
                Clear
              </button>

            )}

          </div>


          {/* ==================================================
              LOADING
          ================================================== */}

          {loading && (

            <div className="history-state">

              <div className="history-state-icon">
                ⏳
              </div>

              <h4>
                Loading scan history...
              </h4>

              <p>
                Sentinel is retrieving your
                security activity.
              </p>

            </div>

          )}


          {/* ==================================================
              ERROR
          ================================================== */}

          {!loading && error && (

            <div className="history-state history-error">

              <div className="history-state-icon">
                ⚠️
              </div>

              <h4>
                Unable to load history
              </h4>

              <p>
                {error}
              </p>

              <button
                type="button"
                className="history-retry"
                onClick={loadHistory}
              >
                Try Again
              </button>

            </div>

          )}


          {/* ==================================================
              EMPTY
          ================================================== */}

          {!loading &&
            !error &&
            scans.length === 0 && (

              <div className="history-state">

                <div className="history-state-icon">
                  📜
                </div>

                <h4>
                  No scans yet
                </h4>

                <p>
                  URLs you scan will appear here.
                </p>

                <button
                  type="button"
                  className="history-retry"
                  onClick={() =>
                    navigate(
                      "/dashboard/url-scanner"
                    )
                  }
                >
                  Scan Your First URL
                </button>

              </div>

            )}


          {/* ==================================================
              NO SEARCH RESULTS
          ================================================== */}

          {!loading &&
            !error &&
            scans.length > 0 &&
            filteredScans.length === 0 && (

              <div className="history-state">

                <div className="history-state-icon">
                  🔎
                </div>

                <h4>
                  No matching scans
                </h4>

                <p>
                  Try another URL or change the
                  status filter.
                </p>

                <button
                  type="button"
                  className="history-clear"
                  onClick={clearFilters}
                >
                  Clear Filters
                </button>

              </div>

            )}


          {/* ==================================================
              SCAN LIST
          ================================================== */}

          {!loading &&
            !error &&
            filteredScans.length > 0 && (

              <div className="history-list">

                {filteredScans.map((scan) => {

                  const status =
                    getStatus(scan);

                  const riskScore =
                    Number(
                      scan?.risk_score || 0
                    );

                  return (

                    <article
                      key={scan.id}
                      className="history-item"
                    >

                      <div className="history-item-icon">

                        {status === "SAFE"
                          ? "🟢"
                          : status ===
                            "SUSPICIOUS"
                          ? "🟡"
                          : "🔴"}

                      </div>


                      <div className="history-item-main">

                        <div className="history-url">
                          {scan.url}
                        </div>

                        <div className="history-date">
                          {formatDate(
                            scan.created_at
                          )}
                        </div>

                      </div>


                      <div className="history-risk">

                        <span>
                          Risk
                        </span>

                        <strong>
                          {riskScore}
                        </strong>

                        <small>
                          / 100
                        </small>

                      </div>


                      <span
                        className={getStatusClass(
                          status
                        )}
                      >
                        {status}
                      </span>


                      <div className="history-actions">

                        {/* VIEW */}

                        <button
                          type="button"
                          title="View details"
                          onClick={() =>
                            setSelectedScan(
                              scan
                            )
                          }
                        >
                          👁️
                        </button>


                        {/* DELETE */}

                        <button
                          type="button"
                          title="Delete scan"
                          onClick={() =>
                            handleDelete(
                              scan.id
                            )
                          }
                        >
                          🗑️
                        </button>

                      </div>

                    </article>

                  );

                })}

              </div>

            )}

        </section>


        {/* ====================================================
            COMPLETE SCAN DETAILS MODAL
        ==================================================== */}

        {selectedScan && (

          <div
            className="history-modal-overlay"
            onClick={() =>
              setSelectedScan(null)
            }
          >

            <div
              className="history-modal"
              onClick={(event) =>
                event.stopPropagation()
              }
            >

              {/* MODAL HEADER */}

              <div className="history-modal-header">

                <div>

                  <span className="section-label">
                    SCAN DETAILS
                  </span>

                  <h3>
                    Security Analysis
                  </h3>

                </div>

                <button
                  type="button"
                  onClick={() =>
                    setSelectedScan(null)
                  }
                  className="history-modal-close"
                  aria-label="Close"
                >
                  ×
                </button>

              </div>


              {/* URL */}

              <div className="history-detail-url">

                <span
                  style={{
                    display: "block",
                    color: "#6f9587",
                    fontSize: "11px",
                    marginBottom: "7px",
                  }}
                >
                  ANALYZED URL
                </span>

                <strong
                  style={{
                    color: "#ffffff",
                    fontSize: "14px",
                    wordBreak: "break-all",
                  }}
                >
                  {selectedScan.url}
                </strong>

              </div>


              {/* ==================================================
                  MAIN RESULT
              ================================================== */}

              <div
                className="history-detail-grid"
                style={{
                  marginTop: "16px",
                }}
              >

                {/* RISK SCORE */}

                <div>

                  <span>
                    Risk Score
                  </span>

                  <strong>
                    {formatNumber(
                      selectedScan.risk_score
                    )}

                    <small>
                      {" "} / 100
                    </small>
                  </strong>

                </div>


                {/* FINAL VERDICT */}

                <div>

                  <span>
                    Final Verdict
                  </span>

                  <strong>
                    {getStatus(
                      selectedScan
                    )}
                  </strong>

                </div>


                {/* SCAN DATE */}

                <div>

                  <span>
                    Scanned At
                  </span>

                  <strong
                    style={{
                      fontSize: "13px",
                    }}
                  >
                    {formatDate(
                      selectedScan.created_at
                    )}
                  </strong>

                </div>

              </div>


              {/* ==================================================
                  RULE ENGINE + ML
              ================================================== */}

              <div
                className="history-detail-grid"
                style={{
                  marginTop: "12px",
                }}
              >

                {/* RULE SCORE */}

                <div>

                  <span>
                    Rule Score
                  </span>

                  <strong>
                    {formatNumber(
                      selectedScan.rule_score
                    )}
                    <small>
                      {" "} / 100
                    </small>
                  </strong>

                </div>


                {/* RULE VERDICT */}

                <div>

                  <span>
                    Rule Verdict
                  </span>

                  <strong>
                    {selectedScan.rule_verdict ||
                      "N/A"}
                  </strong>

                </div>


                {/* ML PROBABILITY */}

                <div>

                  <span>
                    ML Probability
                  </span>

                  <strong>

                    {getMLProbability(
                      selectedScan
                    ) !== null
                      ? `${getMLProbability(
                          selectedScan
                        ).toFixed(2)}%`
                      : "N/A"}

                  </strong>

                </div>

              </div>


              {/* ==================================================
                  ML VERDICT + SOURCE + BRAND
              ================================================== */}

              <div
                className="history-detail-grid"
                style={{
                  marginTop: "12px",
                }}
              >

                {/* ML VERDICT */}

                <div>

                  <span>
                    ML Verdict
                  </span>

                  <strong>
                    {selectedScan.ml_verdict ||
                      "N/A"}
                  </strong>

                </div>


                {/* DETECTION SOURCE */}

                <div>

                  <span>
                    Detection Source
                  </span>

                  <strong
                    style={{
                      fontSize: "13px",
                    }}
                  >
                    {selectedScan.detection_source ||
                      "RULE_ENGINE"}
                  </strong>

                </div>


                {/* BRAND */}

                <div>

                  <span>
                    Brand Impersonation
                  </span>

                  <strong>

                    {selectedScan.brand_impersonation ||
                      "None"}

                  </strong>

                </div>

              </div>


              {/* ==================================================
                  DETECTION ANALYSIS
              ================================================== */}

              <div className="history-reasons">

                <span className="section-label">
                  DETECTION ANALYSIS
                </span>

                {(() => {

                  const reasons =
                    parseReasons(
                      selectedScan
                    );

                  if (
                    reasons.length === 0
                  ) {

                    return (

                      <p>
                        No additional detection
                        reasons were recorded.
                      </p>

                    );

                  }

                  return (

                    <ul>

                      {reasons.map(
                        (reason, index) => (

                          <li
                            key={index}
                          >

                            <span>
                              ✓
                            </span>

                            {String(
                              reason
                            )}

                          </li>

                        )
                      )}

                    </ul>

                  );

                })()}

              </div>


              {/* ==================================================
                  TECHNICAL FEATURES
              ================================================== */}

              {selectedScan.features && (

                <div
                  className="history-reasons"
                  style={{
                    marginTop: "24px",
                  }}
                >

                  <span className="section-label">
                    URL ANALYSIS FEATURES
                  </span>

                  <div
                    className="history-detail-grid"
                    style={{
                      marginTop: "12px",
                    }}
                  >

                    <div>

                      <span>
                        HTTPS
                      </span>

                      <strong>
                        {selectedScan
                          .features
                          .is_https
                          ? "Yes"
                          : "No"}
                      </strong>

                    </div>


                    <div>

                      <span>
                        URL Length
                      </span>

                      <strong>
                        {
                          selectedScan
                            .features
                            .url_length ??
                          "N/A"
                        }
                      </strong>

                    </div>


                    <div>

                      <span>
                        Subdomains
                      </span>

                      <strong>
                        {
                          selectedScan
                            .features
                            .subdomain_count ??
                          "N/A"
                        }
                      </strong>

                    </div>


                    <div>

                      <span>
                        Suspicious Path
                      </span>

                      <strong>
                        {selectedScan
                          .features
                          .has_suspicious_path
                          ? "Yes"
                          : "No"}
                      </strong>

                    </div>


                    <div>

                      <span>
                        Suspicious Query
                      </span>

                      <strong>
                        {selectedScan
                          .features
                          .has_suspicious_query
                          ? "Yes"
                          : "No"}
                      </strong>

                    </div>


                    <div>

                      <span>
                        IP Address
                      </span>

                      <strong>
                        {selectedScan
                          .features
                          .is_ip_address
                          ? "Yes"
                          : "No"}
                      </strong>

                    </div>

                  </div>

                </div>

              )}

            </div>

          </div>

        )}

      </main>

    </div>
  );
}

export default ScanHistory;