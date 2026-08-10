import { useEffect, useState } from "react";
import Sidebar from "../components/dashboard/Sidebar";
import Topbar from "../components/dashboard/Topbar";

const API_URL = "http://127.0.0.1:5000/api/scan";
const HISTORY_API_URL = "http://127.0.0.1:5000/api/history";

function Dashboard() {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // ============================================================
  // USER
  // ============================================================

  const userData = sessionStorage.getItem("user");

  let user = null;

  try {
    user = userData ? JSON.parse(userData) : null;
  } catch {
    user = null;
  }

  const username = user?.username || "User";

  // ============================================================
  // SCANNER STATE
  // ============================================================

  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanResult, setScanResult] = useState(null);

  // ============================================================
  // DASHBOARD STATS
  // ============================================================

  const [stats, setStats] = useState({
    total: 0,
    lowRisk: 0,
    suspicious: 0,
    highRisk: 0,
  });

  // ============================================================
  // RECENT SCANS
  // ============================================================

  const [recentScans, setRecentScans] = useState([]);

  // ============================================================
  // HISTORY LOADING
  // ============================================================

  const [historyLoading, setHistoryLoading] = useState(false);

  // ============================================================
  // GET AUTH TOKEN
  // ============================================================

  const getToken = () => {
    return (
      sessionStorage.getItem("token") ||
      sessionStorage.getItem("access_token") ||
      sessionStorage.getItem("accessToken") ||
      localStorage.getItem("token") ||
      localStorage.getItem("access_token") ||
      localStorage.getItem("accessToken") ||
      ""
    );
  };

  // ============================================================
  // NORMALIZE HISTORY RESPONSE
  // ============================================================

  const normalizeHistory = (data) => {
    let rawScans = [];

    if (Array.isArray(data)) {
      rawScans = data;
    } else if (Array.isArray(data?.history)) {
      rawScans = data.history;
    } else if (Array.isArray(data?.scans)) {
      rawScans = data.scans;
    } else if (Array.isArray(data?.results)) {
      rawScans = data.results;
    } else if (Array.isArray(data?.data)) {
      rawScans = data.data;
    }

    return rawScans.map((item, index) => {
      const verdict = String(
        item?.verdict ||
          item?.result ||
          item?.status ||
          "SAFE"
      ).toUpperCase();

      const riskScore = Number(
        item?.risk_score ??
          item?.riskScore ??
          item?.score ??
          0
      );

      const scanUrl =
        item?.url ||
        item?.input_data ||
        item?.inputData ||
        item?.URL ||
        "Unknown URL";

      const rawTimestamp =
        item?.timestamp ||
        item?.created_at ||
        item?.createdAt ||
        item?.scanned_at ||
        item?.scannedAt ||
        item?.date ||
        null;

      let timestamp = "Previously scanned";

      if (rawTimestamp) {
        const parsedDate = new Date(rawTimestamp);

        if (!Number.isNaN(parsedDate.getTime())) {
          timestamp = parsedDate.toLocaleString();
        }
      }

      return {
        id:
          item?.scan_id ??
          item?.scanId ??
          item?.id ??
          `history-${index}`,

        url: scanUrl,

        riskScore: Number.isFinite(riskScore)
          ? riskScore
          : 0,

        verdict,

        mlProbability:
          item?.ml_probability ??
          item?.mlProbability ??
          null,

        mlVerdict:
          item?.ml_verdict ??
          item?.mlVerdict ??
          null,

        ruleScore:
          item?.rule_score ??
          item?.ruleScore ??
          null,

        ruleVerdict:
          item?.rule_verdict ??
          item?.ruleVerdict ??
          null,

        timestamp,
      };
    });
  };

  // ============================================================
  // LOAD HISTORY FROM DATABASE
  // ============================================================

  const loadHistory = async () => {
    const token = getToken();

    if (!token) {
      console.warn(
        "History cannot be loaded: authentication token missing."
      );
      return;
    }

    setHistoryLoading(true);

    try {
      const response = await fetch(HISTORY_API_URL, {
        method: "GET",

        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data?.msg ||
            data?.error ||
            "Unable to load scan history."
        );
      }

      const scans = normalizeHistory(data);

      // --------------------------------------------------------
      // SORT NEWEST FIRST
      // --------------------------------------------------------

      scans.sort((a, b) => {
        const aDate = Date.parse(a.timestamp);
        const bDate = Date.parse(b.timestamp);

        if (
          Number.isFinite(aDate) &&
          Number.isFinite(bDate)
        ) {
          return bDate - aDate;
        }

        return 0;
      });

      // --------------------------------------------------------
      // RECENT SCANS
      // --------------------------------------------------------

      setRecentScans(scans.slice(0, 5));

      // --------------------------------------------------------
      // CALCULATE STATISTICS
      // --------------------------------------------------------

      let total = scans.length;
      let lowRisk = 0;
      let suspicious = 0;
      let highRisk = 0;

      scans.forEach((scan) => {
        const verdict = String(
          scan.verdict || ""
        ).toUpperCase();

        if (verdict === "SAFE") {
          lowRisk += 1;
        } else if (verdict === "SUSPICIOUS") {
          suspicious += 1;
        } else if (
          verdict === "HIGH RISK" ||
          verdict === "CRITICAL"
        ) {
          highRisk += 1;
        }
      });

      // --------------------------------------------------------
      // USE BACKEND TOTAL IF AVAILABLE
      // --------------------------------------------------------

      const backendTotal =
        data?.total ??
        data?.total_scans ??
        data?.totalScans ??
        data?.count ??
        null;

      if (
        typeof backendTotal === "number" &&
        backendTotal >= total
      ) {
        total = backendTotal;
      }

      setStats({
        total,
        lowRisk,
        suspicious,
        highRisk,
      });

    } catch (error) {
      console.error(
        "History loading error:",
        error
      );
    } finally {
      setHistoryLoading(false);
    }
  };

  // ============================================================
  // LOAD HISTORY WHEN DASHBOARD OPENS
  // ============================================================

  useEffect(() => {
    loadHistory();
  }, []);

  // ============================================================
  // SCAN URL
  // ============================================================

  const handleScan = async () => {
    setScanError("");

    // ----------------------------------------------------------
    // VALIDATION
    // ----------------------------------------------------------

    if (!url.trim()) {
      setScanError(
        "Please enter a URL to scan."
      );
      return;
    }

    // ----------------------------------------------------------
    // TOKEN
    // ----------------------------------------------------------

    const token = getToken();

    if (!token) {
      setScanError(
        "Authentication token not found. Please login again."
      );
      return;
    }

    setScanning(true);
    setScanResult(null);

    try {
      // --------------------------------------------------------
      // CALL SCAN API
      // --------------------------------------------------------

      const response = await fetch(API_URL, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },

        body: JSON.stringify({
          url: url.trim(),
        }),
      });

      const data = await response.json();

      // --------------------------------------------------------
      // API ERROR
      // --------------------------------------------------------

      if (!response.ok) {
        throw new Error(
          data?.msg ||
            data?.error ||
            "Unable to scan this URL."
        );
      }

      // --------------------------------------------------------
      // SCAN ERROR
      // --------------------------------------------------------

      if (!data.success) {
        throw new Error(
          data?.error ||
            "URL scanning failed."
        );
      }

      // --------------------------------------------------------
      // SHOW CURRENT RESULT
      // --------------------------------------------------------

      setScanResult(data);

      // --------------------------------------------------------
      // IMPORTANT:
      // Reload database history after every scan.
      // This makes Total Scans and Recent Scans persistent.
      // --------------------------------------------------------

      await loadHistory();

    } catch (error) {
      console.error(
        "URL scan error:",
        error
      );

      setScanError(
        error?.message ||
          "Something went wrong while scanning."
      );

    } finally {
      setScanning(false);
    }
  };

  // ============================================================
  // ENTER KEY
  // ============================================================

  const handleKeyDown = (event) => {
    if (
      event.key === "Enter" &&
      !scanning
    ) {
      handleScan();
    }
  };

  // ============================================================
  // RESULT CLASS
  // ============================================================

  const getVerdictClass = (verdict) => {
    const normalized = String(
      verdict || ""
    ).toLowerCase();

    if (normalized === "safe") {
      return "safe";
    }

    if (normalized === "suspicious") {
      return "suspicious";
    }

    if (normalized === "high risk") {
      return "high-risk";
    }

    if (normalized === "critical") {
      return "critical";
    }

    return "unknown";
  };

  // ============================================================
  // DASHBOARD
  // ============================================================

  return (
    <div className="dashboard">

      {/* ======================================================
          SIDEBAR
      ====================================================== */}

      <Sidebar
        isOpen={sidebarOpen}
        onClose={() =>
          setSidebarOpen(false)
        }
      />

      {/* ======================================================
          MAIN AREA
      ====================================================== */}

      <div className="dashboard-main">

        {/* ====================================================
            TOPBAR
        ==================================================== */}

        <Topbar
          onMenuClick={() =>
            setSidebarOpen(true)
          }
        />

        {/* ====================================================
            DASHBOARD CONTENT
        ==================================================== */}

        <main className="dashboard-content">

          {/* ==================================================
              WELCOME
          ================================================== */}

          <section className="dashboard-welcome">

            <div>

              <span className="dashboard-eyebrow">
                SECURITY OVERVIEW
              </span>

              <h2>
                Good morning, {username} 👋
              </h2>

              <p>
                Stay alert, understand the risk,
                and think before you trust.
              </p>

            </div>

          </section>

          {/* ==================================================
              OVERVIEW CARDS
          ================================================== */}

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
                  {stats.total}
                </strong>

              </div>

            </div>

            {/* LOW RISK */}

            <div className="stat-card">

              <div className="stat-icon">
                🟢
              </div>

              <div>

                <span>
                  Low Risk
                </span>

                <strong>
                  {stats.lowRisk}
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
                  {stats.suspicious}
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
                  {stats.highRisk}
                </strong>

              </div>

            </div>

          </section>

          {/* ==================================================
              REAL-TIME URL SCANNER
          ================================================== */}

          <section className="realtime-monitor">

            <div className="section-header">

              <div>

                <span className="section-label">
                  REAL-TIME SECURITY
                </span>

                <h3>
                  Live Threat Monitor
                </h3>

                <p>
                  Analyze a URL instantly using
                  Sentinel's rule engine and
                  machine learning model.
                </p>

              </div>

              <div className="live-status">

                <span className="live-status-dot">
                  ●
                </span>

                LIVE

              </div>

            </div>

            {/* ==================================================
                URL INPUT
            ================================================== */}

            <div className="url-scanner">

              <div className="url-input-wrapper">

                <span className="url-input-icon">
                  🔗
                </span>

                <input
                  type="text"
                  value={url}
                  onChange={(event) =>
                    setUrl(event.target.value)
                  }
                  onKeyDown={handleKeyDown}
                  placeholder="Enter a suspicious URL to scan..."
                  disabled={scanning}
                />

                <button
                  type="button"
                  onClick={handleScan}
                  disabled={scanning}
                >
                  {scanning
                    ? "Scanning..."
                    : "Scan URL"}
                </button>

              </div>

              {/* ==================================================
                  ERROR
              ================================================== */}

              {scanError && (

                <div className="scan-error">
                  ⚠️ {scanError}
                </div>

              )}

              {/* ==================================================
                  SCANNING
              ================================================== */}

              {scanning && (

                <div className="scan-loading">

                  <div className="scan-loading-spinner">
                    ⟳
                  </div>

                  <div>

                    <strong>
                      Sentinel is analyzing the URL...
                    </strong>

                    <p>
                      Extracting features and
                      evaluating security indicators.
                    </p>

                  </div>

                </div>

              )}

              {/* ==================================================
                  SCAN RESULT
              ================================================== */}

              {scanResult &&
                !scanning && (

                <div
                  className={`scan-result ${getVerdictClass(
                    scanResult.verdict
                  )}`}
                >

                  {/* RESULT HEADER */}

                  <div className="scan-result-header">

                    <div>

                      <span className="section-label">
                        SCAN RESULT
                      </span>

                      <h4>
                        {scanResult.verdict}
                      </h4>

                      <p>
                        {scanResult.url}
                      </p>

                    </div>

                    <div className="risk-score-display">

                      <span>
                        Risk Score
                      </span>

                      <strong>
                        {scanResult.risk_score}
                      </strong>

                      <small>
                        / 100
                      </small>

                    </div>

                  </div>

                  {/* ==================================================
                      RISK INFORMATION
                  ================================================== */}

                  <div className="scan-result-metrics">

                    {/* RULE SCORE */}

                    <div className="result-metric">

                      <span>
                        Rule Score
                      </span>

                      <strong>
                        {scanResult.rule_score ??
                          "—"}
                      </strong>

                    </div>

                    {/* RULE VERDICT */}

                    <div className="result-metric">

                      <span>
                        Rule Verdict
                      </span>

                      <strong>
                        {scanResult.rule_verdict ||
                          "—"}
                      </strong>

                    </div>

                    {/* ML PROBABILITY */}

                    <div className="result-metric">

                      <span>
                        ML Probability
                      </span>

                      <strong>
                        {scanResult.ml_probability != null
                          ? `${scanResult.ml_probability}%`
                          : "—"}
                      </strong>

                    </div>

                    {/* ML VERDICT */}

                    <div className="result-metric">

                      <span>
                        ML Verdict
                      </span>

                      <strong>
                        {scanResult.ml_verdict ||
                          "—"}
                      </strong>

                    </div>

                  </div>

                  {/* ==================================================
                      SECURITY INTELLIGENCE
                  ================================================== */}

                  {(scanResult.detection_source ||
                    scanResult.brand_impersonation ||
                    scanResult.trusted_domain != null) && (

                    <div className="scan-result-metrics">

                      {/* DETECTION SOURCE */}

                      {scanResult.detection_source && (

                        <div className="result-metric">

                          <span>
                            Detection Source
                          </span>

                          <strong>
                            {String(
                              scanResult.detection_source
                            ).replaceAll(
                              "_",
                              " "
                            )}
                          </strong>

                        </div>

                      )}

                      {/* TRUSTED DOMAIN */}

                      {scanResult.trusted_domain != null && (

                        <div className="result-metric">

                          <span>
                            Trusted Domain
                          </span>

                          <strong>
                            {scanResult.trusted_domain
                              ? "YES"
                              : "NO"}
                          </strong>

                        </div>

                      )}

                      {/* BRAND */}

                      {scanResult.brand_impersonation && (

                        <div className="result-metric">

                          <span>
                            Brand Impersonation
                          </span>

                          <strong>
                            {scanResult.brand_impersonation}
                          </strong>

                        </div>

                      )}

                    </div>

                  )}

                  {/* ==================================================
                      DETECTION REASONS
                  ================================================== */}

                  <div className="scan-reasons">

                    <h5>
                      Detection Analysis
                    </h5>

                    {Array.isArray(
                      scanResult.reasons
                    ) &&
                    scanResult.reasons.length > 0 ? (

                      <ul>

                        {scanResult.reasons.map(
                          (reason, index) => (

                            <li key={index}>

                              <span>
                                ✓
                              </span>

                              {reason}

                            </li>

                          )
                        )}

                      </ul>

                    ) : (

                      <p>
                        No significant suspicious
                        indicators detected.
                      </p>

                    )}

                  </div>

                </div>

              )}

            </div>

          </section>

          {/* ==================================================
              WHAT DO YOU WANT TO CHECK
          ================================================== */}

          <section className="scan-options">

            <div className="section-header">

              <div>

                <span className="section-label">
                  SCAM DETECTION
                </span>

                <h3>
                  What do you want to check?
                </h3>

                <p>
                  Choose what you want
                  Sentinel to analyze.
                </p>

              </div>

            </div>

            <div className="scan-option-grid">

              {/* URL */}

              <button
                type="button"
                className="scan-option-card available"
                onClick={() => {
                  document
                    .querySelector(
                      ".url-input-wrapper input"
                    )
                    ?.focus();
                }}
              >

                <span className="scan-option-icon">
                  🔗
                </span>

                <div>

                  <h4>
                    URL Scanner
                  </h4>

                  <p>
                    Check suspicious website links.
                  </p>

                </div>

                <span className="option-status available-status">
                  Available
                </span>

              </button>

              {/* SMS */}

              <button
                type="button"
                className="scan-option-card"
              >

                <span className="scan-option-icon">
                  📱
                </span>

                <div>

                  <h4>
                    SMS Scanner
                  </h4>

                  <p>
                    Analyze suspicious messages.
                  </p>

                </div>

                <span className="option-status">
                  Coming Soon
                </span>

              </button>

              {/* EMAIL */}

              <button
                type="button"
                className="scan-option-card"
              >

                <span className="scan-option-icon">
                  📧
                </span>

                <div>

                  <h4>
                    Email Scanner
                  </h4>

                  <p>
                    Detect phishing and email scams.
                  </p>

                </div>

                <span className="option-status">
                  Coming Soon
                </span>

              </button>

              {/* FAKE JOB */}

              <button
                type="button"
                className="scan-option-card"
              >

                <span className="scan-option-icon">
                  💼
                </span>

                <div>

                  <h4>
                    Fake Job Detector
                  </h4>

                  <p>
                    Identify suspicious job offers.
                  </p>

                </div>

                <span className="option-status">
                  Coming Soon
                </span>

              </button>

              {/* INVESTMENT */}

              <button
                type="button"
                className="scan-option-card"
              >

                <span className="scan-option-icon">
                  💰
                </span>

                <div>

                  <h4>
                    Investment Detector
                  </h4>

                  <p>
                    Check suspicious investment offers.
                  </p>

                </div>

                <span className="option-status">
                  Coming Soon
                </span>

              </button>

              {/* SCREENSHOT */}

              <button
                type="button"
                className="scan-option-card"
              >

                <span className="scan-option-icon">
                  🖼️
                </span>

                <div>

                  <h4>
                    Screenshot Scanner
                  </h4>

                  <p>
                    Analyze screenshots for scam indicators.
                  </p>

                </div>

                <span className="option-status">
                  Coming Soon
                </span>

              </button>

            </div>

          </section>

          {/* ==================================================
              RECENT SCANS
          ================================================== */}

          <section className="recent-scans">

            <div className="section-header">

              <div>

                <span className="section-label">
                  ACTIVITY
                </span>

                <h3>
                  Recent Scans
                </h3>

                <p>
                  Your latest security checks
                  will appear here.
                </p>

              </div>

              <button
                type="button"
                className="history-refresh-button"
                onClick={loadHistory}
                disabled={historyLoading}
              >
                {historyLoading
                  ? "Loading..."
                  : "↻ Refresh"}
              </button>

            </div>

            {recentScans.length === 0 ? (

              <div className="recent-scans-empty">

                <span>
                  📜
                </span>

                <p>
                  No scans yet.
                </p>

                <small>
                  Your scan history will appear
                  here after you analyze something.
                </small>

              </div>

            ) : (

              <div className="recent-scans-list">

                {recentScans.map(
                  (scan) => (

                    <div
                      className="recent-scan-item"
                      key={scan.id}
                    >

                      <div className="recent-scan-icon">
                        🔗
                      </div>

                      <div className="recent-scan-info">

                        <strong>
                          {scan.url}
                        </strong>

                        <small>
                          Scanned at{" "}
                          {scan.timestamp}
                        </small>

                      </div>

                      <div className="recent-scan-risk">

                        <strong>
                          {scan.riskScore}/100
                        </strong>

                        <span
                          className={getVerdictClass(
                            scan.verdict
                          )}
                        >
                          {scan.verdict}
                        </span>

                      </div>

                    </div>

                  )
                )}

              </div>

            )}

          </section>

          {/* ==================================================
              AWARENESS TIP
          ================================================== */}

          <section className="dashboard-awareness">

            <div className="awareness-tip-icon">
              🧠
            </div>

            <div>

              <span className="section-label">
                SECURITY TIP
              </span>

              <h3>
                Think before you click.
              </h3>

              <p>
                Scammers often create urgency
                to stop you from thinking carefully.
                Take a moment to verify unexpected
                links, messages, and offers.
              </p>

            </div>

          </section>

        </main>

      </div>

    </div>
  );
}

export default Dashboard;