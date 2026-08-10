import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  Link,
} from "react-router-dom";

import "./App.css";

import Login from "./pages/Login";
import Register from "./pages/Register";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";

import Dashboard from "./pages/Dashboard";
import URLScanner from "./pages/URLScanner";
import ScanHistory from "./pages/ScanHistory";

// ============================================================
// PROTECTED ROUTE
// ============================================================

function ProtectedRoute({ children }) {
  const token = sessionStorage.getItem("access_token");

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

// ============================================================
// HOME
// ============================================================

function Home() {
  return (
    <div className="app">

      {/* Navbar */}
      <header>
        <div className="navbar">

          <Link to="/" className="logo">
            🛡️ Sentinel AI
          </Link>

          <nav className="nav-links">

            <a href="#how-it-works">
              How It Works
            </a>

            <a href="#awareness">
              Awareness
            </a>

            <Link
              to="/login"
              className="login-btn"
            >
              Login
            </Link>

            <Link
              to="/register"
              className="signup-btn"
            >
              Sign Up
            </Link>

          </nav>

        </div>
      </header>


      {/* Hero */}
      <main>

        <section className="hero">

          <div className="hero-content">

            <div className="badge">
              🛡️ AI-Powered Scam Awareness
            </div>

            <h1>
              Stay One Step
              <span> Ahead of Scams.</span>
            </h1>

            <p className="hero-text">
              Check suspicious website links, understand the risks,
              and learn how to stay safe online.
            </p>


            {/* Scanner Box */}
            <div className="scanner-box">

              <div className="input-wrapper">

                <span>
                  🔗
                </span>

                <input
                  type="text"
                  placeholder="Enter a website URL..."
                />

              </div>

              <Link
                to="/dashboard/url-scanner"
                className="scan-btn"
              >
                🔍 Scan URL
              </Link>

            </div>

            <p className="scanner-note">
              Don't know if a link is safe? Let Sentinel help you
              understand it.
            </p>

          </div>


          {/* Hero Visual */}
          <div className="hero-card">

            <div className="status-header">

              <span>
                Sentinel Analysis
              </span>

              <span className="live-dot">
                ● Live
              </span>

            </div>


            <div className="risk-circle">

              <div className="risk-number">
                24
              </div>

              <div className="risk-label">
                Risk Score
              </div>

            </div>


            <div className="safe-status">

              <span>
                ✓
              </span>

              Low Risk

            </div>


            <div className="analysis-list">

              <div>

                <span>
                  HTTPS Connection
                </span>

                <strong className="safe">
                  ✓
                </strong>

              </div>


              <div>

                <span>
                  Suspicious Keywords
                </span>

                <strong className="safe">
                  ✓
                </strong>

              </div>


              <div>

                <span>
                  Domain Analysis
                </span>

                <strong className="warning">
                  !
                </strong>

              </div>

            </div>


            <div className="analysis-tip">
              💡 Sentinel explains <strong>why</strong> a website
              may be risky.
            </div>

          </div>

        </section>


        {/* Trust Indicators */}
        <section className="features">

          <div className="feature-item">

            <span>
              🔍
            </span>

            <div>

              <strong>
                Detect
              </strong>

              <p>
                Find suspicious indicators
              </p>

            </div>

          </div>


          <div className="feature-item">

            <span>
              🧠
            </span>

            <div>

              <strong>
                Understand
              </strong>

              <p>
                Know why a link is risky
              </p>

            </div>

          </div>


          <div className="feature-item">

            <span>
              🛡️
            </span>

            <div>

              <strong>
                Protect
              </strong>

              <p>
                Learn safer online habits
              </p>

            </div>

          </div>

        </section>


        {/* How It Works */}
        <section
          className="section"
          id="how-it-works"
        >

          <div className="section-heading">

            <span className="section-label">
              HOW IT WORKS
            </span>

            <h2>
              Security doesn't have to be complicated.
            </h2>

            <p>
              Sentinel makes website safety easier to understand
              in three simple steps.
            </p>

          </div>


          <div className="steps">

            <div className="step-card">

              <div className="step-number">
                01
              </div>

              <div className="step-icon">
                🔗
              </div>

              <h3>
                Paste a Link
              </h3>

              <p>
                Enter the website URL you want to check.
              </p>

            </div>


            <div className="step-card">

              <div className="step-number">
                02
              </div>

              <div className="step-icon">
                🔍
              </div>

              <h3>
                Sentinel Analyzes
              </h3>

              <p>
                We check multiple indicators that can reveal
                suspicious patterns.
              </p>

            </div>


            <div className="step-card">

              <div className="step-number">
                03
              </div>

              <div className="step-icon">
                🛡️
              </div>

              <h3>
                Understand the Result
              </h3>

              <p>
                Get a clear risk score, reasons, and safety advice.
              </p>

            </div>

          </div>

        </section>


        {/* Awareness */}
        <section
          className="awareness-section"
          id="awareness"
        >

          <div className="awareness-content">

            <span className="section-label">
              ONLINE AWARENESS
            </span>

            <h2>
              Don't just detect scams.
              <span>
                Learn to recognize them.
              </span>
            </h2>

            <p>
              Sentinel is designed to help you understand common
              warning signs instead of simply telling you
              "safe" or "unsafe".
            </p>

          </div>


          <div className="tips">

            <div className="tip">

              <span>
                ⚠️
              </span>

              <div>

                <h3>
                  Check the URL
                </h3>

                <p>
                  Look carefully for strange spellings, extra
                  characters, or unusual domains.
                </p>

              </div>

            </div>


            <div className="tip">

              <span>
                🔐
              </span>

              <div>

                <h3>
                  Protect Your Credentials
                </h3>

                <p>
                  Never share passwords, OTPs, or banking details
                  just because a website asks for them.
                </p>

              </div>

            </div>


            <div className="tip">

              <span>
                🎯
              </span>

              <div>

                <h3>
                  Don't Rush
                </h3>

                <p>
                  Urgent messages and limited-time offers are
                  common tactics used by scammers.
                </p>

              </div>

            </div>

          </div>

        </section>


        {/* CTA */}
        <section className="cta">

          <div>

            <span>
              READY TO CHECK A LINK?
            </span>

            <h2>
              Think before you click.
            </h2>

            <p>
              Use Sentinel to understand suspicious websites
              before trusting them.
            </p>

          </div>

          <Link
            to="/dashboard/url-scanner"
            className="cta-btn"
          >
            🔍 Scan a URL
          </Link>

        </section>

      </main>


      {/* Footer */}
      <footer>

        <div className="footer-logo">
          🛡️ Sentinel AI
        </div>

        <p>
          Detect scams. Understand the risk. Stay safe.
        </p>

        <span>
          © 2026 Sentinel AI
        </span>

      </footer>

    </div>
  );
}

// ============================================================
// APP
// ============================================================

function App() {
  return (
    <BrowserRouter>

      <Routes>

        {/* ==================================================
            PUBLIC HOME
            ================================================== */}

        <Route
          path="/"
          element={<Home />}
        />


        {/* ==================================================
            AUTHENTICATION
            ================================================== */}

        <Route
          path="/login"
          element={<Login />}
        />

        <Route
          path="/register"
          element={<Register />}
        />

        <Route
          path="/forgot-password"
          element={<ForgotPassword />}
        />

        <Route
          path="/reset-password"
          element={<ResetPassword />}
        />


        {/* ==================================================
            PROTECTED DASHBOARD
            ================================================== */}

        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />


        {/* ==================================================
            PROTECTED URL SCANNER
            ================================================== */}

        <Route
          path="/dashboard/url-scanner"
          element={
            <ProtectedRoute>
              <URLScanner />
            </ProtectedRoute>
          }
        />


        {/* ==================================================
            PROTECTED SCAN HISTORY
            ================================================== */}

        <Route
          path="/dashboard/history"
          element={
            <ProtectedRoute>
              <ScanHistory />
            </ProtectedRoute>
          }
        />


        {/* ==================================================
            UNKNOWN ROUTE
            ================================================== */}

        <Route
          path="*"
          element={
            <Navigate
              to="/"
              replace
            />
          }
        />

      </Routes>

    </BrowserRouter>
  );
}

export default App;