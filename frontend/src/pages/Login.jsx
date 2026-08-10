import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";

function Login() {
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [showPassword, setShowPassword] = useState(false);

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
        "http://127.0.0.1:5000/api/auth/login",
        {
          email,
          password,
        }
      );

      if (response.data.success) {
        // Store JWT token
        sessionStorage.setItem(
          "access_token",
          response.data.access_token
        );

        // Store user information
        sessionStorage.setItem(
          "user",
          JSON.stringify(response.data.user)
        );

        setSuccess("Login successful.");

        setPassword("");

        // Go to protected dashboard
        navigate("/dashboard");
      }
    } catch (err) {
      if (err.response && err.response.data) {
        setError(
          err.response.data.error ||
            "Login failed. Please try again."
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

        {/* Logo */}
        <div className="auth-logo">
          🛡️
        </div>

        <h1>
          Welcome back
        </h1>

        <p className="auth-subtitle">
          Login to continue protecting yourself from scams.
        </p>

        <form onSubmit={handleSubmit}>

          {/* Email */}
          <label htmlFor="email">
            Email
          </label>

          <input
            id="email"
            type="email"
            placeholder="Enter your email"
            value={email}
            onChange={(e) =>
              setEmail(e.target.value)
            }
            required
          />


          {/* Password */}
          <label htmlFor="password">
            Password
          </label>

          <div className="password-input-wrapper">

            <input
              id="password"
              type={
                showPassword
                  ? "text"
                  : "password"
              }
              placeholder="Enter your password"
              value={password}
              onChange={(e) =>
                setPassword(e.target.value)
              }
              required
            />

            <button
              type="button"
              className="password-toggle"
              onClick={() =>
                setShowPassword(!showPassword)
              }
              aria-label={
                showPassword
                  ? "Hide password"
                  : "Show password"
              }
            >
              {showPassword ? "🙈" : "👁️"}
            </button>

          </div>


          {/* Forgot Password */}
          <div className="forgot-password-wrapper">

            <Link
              to="/forgot-password"
              className="forgot-password-link"
            >
              Forgot Password?
            </Link>

          </div>


          {/* Error */}
          {error && (
            <p className="form-message error">
              ✕ {error}
            </p>
          )}


          {/* Success */}
          {success && (
            <p className="form-message success">
              ✓ {success}
            </p>
          )}


          {/* Login Button */}
          <button
            type="submit"
            className="auth-button"
            disabled={loading}
          >
            {loading
              ? "Logging in..."
              : "Login"}
          </button>

        </form>


        {/* Register */}
        <p className="auth-switch">
          Don't have an account?{" "}

          <Link to="/register">
            Sign Up
          </Link>
        </p>


        {/* Back Home */}
        <Link
          to="/"
          className="back-home"
        >
          ← Back to Sentinel
        </Link>

      </div>
    </div>
  );
}

export default Login;