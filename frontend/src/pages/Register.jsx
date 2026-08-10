import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";

function Register() {
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const passwordRules = {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    special: /[^A-Za-z0-9\s]/.test(password),
    noSpaces: !/\s/.test(password),
  };

  const isPasswordStrong =
    passwordRules.length &&
    passwordRules.uppercase &&
    passwordRules.lowercase &&
    passwordRules.number &&
    passwordRules.special &&
    passwordRules.noSpaces;

  const passwordsMatch =
    password.length > 0 &&
    confirmPassword.length > 0 &&
    password === confirmPassword;

  const handleSubmit = async (e) => {
    e.preventDefault();

    setError("");
    setSuccess("");

    if (!isPasswordStrong) {
      setError("Please create a strong password.");
      return;
    }

    if (!passwordsMatch) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);

    try {
      const response = await axios.post(
        "http://127.0.0.1:5000/api/auth/register",
        {
          username,
          email,
          password,
        }
      );

      if (response.data.success) {
        setSuccess("Account created successfully. Redirecting to Login...");

        setUsername("");
        setEmail("");
        setPassword("");
        setConfirmPassword("");

        setTimeout(() => {
          navigate("/login");
        }, 1500);
      }
    } catch (err) {
      if (err.response && err.response.data) {
        setError(
          err.response.data.error ||
            "Registration failed. Please try again."
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

        <h1>Create your account</h1>

        <p className="auth-subtitle">
          Create your Sentinel account to stay protected from scams.
        </p>

        <form onSubmit={handleSubmit}>
          {/* Username */}
          <label htmlFor="username">Username</label>

          <input
            id="username"
            type="text"
            placeholder="Enter your username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            minLength={3}
            maxLength={30}
            required
          />

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

          {/* Password */}
          <label htmlFor="password">Password</label>

          <input
            id="password"
            type="password"
            placeholder="Create a strong password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />

          {/* Password Rules */}
          <div className="password-rules">
            <p>Password must contain:</p>

            <div
              className={
                passwordRules.length ? "rule valid" : "rule"
              }
            >
              {passwordRules.length ? "✓" : "○"} At least 8 characters
            </div>

            <div
              className={
                passwordRules.uppercase ? "rule valid" : "rule"
              }
            >
              {passwordRules.uppercase ? "✓" : "○"} One uppercase letter
            </div>

            <div
              className={
                passwordRules.lowercase ? "rule valid" : "rule"
              }
            >
              {passwordRules.lowercase ? "✓" : "○"} One lowercase letter
            </div>

            <div
              className={
                passwordRules.number ? "rule valid" : "rule"
              }
            >
              {passwordRules.number ? "✓" : "○"} One number
            </div>

            <div
              className={
                passwordRules.special ? "rule valid" : "rule"
              }
            >
              {passwordRules.special ? "✓" : "○"} One special character
            </div>

            <div
              className={
                passwordRules.noSpaces ? "rule valid" : "rule"
              }
            >
              {passwordRules.noSpaces ? "✓" : "○"} No spaces
            </div>
          </div>

          {/* Confirm Password */}
          <label htmlFor="confirmPassword">Confirm Password</label>

          <input
            id="confirmPassword"
            type="password"
            placeholder="Confirm your password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />

          {confirmPassword.length > 0 && (
            <p
              className={
                passwordsMatch
                  ? "password-match success"
                  : "password-match error"
              }
            >
              {passwordsMatch
                ? "✓ Passwords match"
                : "✕ Passwords do not match"}
            </p>
          )}

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
            disabled={!isPasswordStrong || !passwordsMatch || loading}
          >
            {loading ? "Creating Account..." : "Sign Up"}
          </button>
        </form>

        <p className="auth-switch">
          Already have an account?{" "}
          <Link to="/login">Login</Link>
        </p>

        <Link to="/" className="back-home">
          ← Back to Sentinel
        </Link>
      </div>
    </div>
  );
}

export default Register;