import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";

function ForgotPassword() {
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();

    setError("");
    setSuccess("");
    setLoading(true);

    try {
      const response = await axios.post(
        "http://127.0.0.1:5000/api/auth/forgot-password",
        {
          email,
        }
      );

      if (response.data.success) {
        // Development mode only:
        // Backend returns the reset token so we can test locally.
        if (response.data.reset_token) {
          sessionStorage.setItem(
            "reset_token",
            response.data.reset_token
          );

          setSuccess(
            "Reset request created. Redirecting to password reset..."
          );

          setTimeout(() => {
            navigate("/reset-password");
          }, 1200);
        } else {
          setSuccess(
            "If an account exists for this email, a password reset request has been created."
          );
        }
      }
    } catch (err) {
      if (err.response && err.response.data) {
        setError(
          err.response.data.error ||
            "Unable to process your request. Please try again."
        );
      } else {
        setError(
          "Unable to connect to Sentinel server. Please make sure the backend is running."
        );
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-logo">🛡️</div>

        <h1>Forgot Password?</h1>

        <p className="auth-subtitle">
          Enter your email address and we'll help you reset your password.
        </p>

        <form onSubmit={handleSubmit}>
          {/* Email */}
          <label htmlFor="email">Email</label>

          <input
            id="email"
            type="email"
            placeholder="Enter your email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />

          {/* Error Message */}
          {error && (
            <p className="form-message error">
              ✕ {error}
            </p>
          )}

          {/* Success Message */}
          {success && (
            <p className="form-message success">
              ✓ {success}
            </p>
          )}

          {/* Submit */}
          <button
            type="submit"
            className="auth-button"
            disabled={loading}
          >
            {loading
              ? "Processing..."
              : "Continue"}
          </button>
        </form>

        <p className="auth-switch">
          Remember your password?{" "}
          <Link to="/login">Login</Link>
        </p>

        <Link to="/" className="back-home">
          ← Back to Sentinel
        </Link>
      </div>
    </div>
  );
}

export default ForgotPassword;