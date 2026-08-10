import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";

function ResetPassword() {
  const navigate = useNavigate();

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const resetToken = sessionStorage.getItem("reset_token");

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

    if (!resetToken) {
      setError(
        "Reset session not found. Please request a new password reset."
      );
      return;
    }

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
        "http://127.0.0.1:5000/api/auth/reset-password",
        {
          reset_token: resetToken,
          password,
          confirm_password: confirmPassword,
        }
      );

      if (response.data.success) {
        sessionStorage.removeItem("reset_token");

        setSuccess(
          "Password reset successfully. Redirecting to Login..."
        );

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
            "Unable to reset password. Please try again."
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

        <h1>Reset Password</h1>

        <p className="auth-subtitle">
          Create a new strong password for your Sentinel account.
        </p>

        <form onSubmit={handleSubmit}>
          {/* New Password */}
          <label htmlFor="password">
            New Password
          </label>

          <div className="password-input-wrapper">
            <input
              id="password"
              type={showPassword ? "text" : "password"}
              placeholder="Create a strong password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
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

          {/* Password Rules */}
          <div className="password-rules">
            <p>Password must contain:</p>

            <div
              className={
                passwordRules.length
                  ? "rule valid"
                  : "rule"
              }
            >
              {passwordRules.length ? "✓" : "○"} At least 8 characters
            </div>

            <div
              className={
                passwordRules.uppercase
                  ? "rule valid"
                  : "rule"
              }
            >
              {passwordRules.uppercase ? "✓" : "○"} One uppercase letter
            </div>

            <div
              className={
                passwordRules.lowercase
                  ? "rule valid"
                  : "rule"
              }
            >
              {passwordRules.lowercase ? "✓" : "○"} One lowercase letter
            </div>

            <div
              className={
                passwordRules.number
                  ? "rule valid"
                  : "rule"
              }
            >
              {passwordRules.number ? "✓" : "○"} One number
            </div>

            <div
              className={
                passwordRules.special
                  ? "rule valid"
                  : "rule"
              }
            >
              {passwordRules.special ? "✓" : "○"} One special character
            </div>

            <div
              className={
                passwordRules.noSpaces
                  ? "rule valid"
                  : "rule"
              }
            >
              {passwordRules.noSpaces ? "✓" : "○"} No spaces
            </div>
          </div>

          {/* Confirm Password */}
          <label htmlFor="confirmPassword">
            Confirm New Password
          </label>

          <div className="password-input-wrapper">
            <input
              id="confirmPassword"
              type={
                showConfirmPassword
                  ? "text"
                  : "password"
              }
              placeholder="Confirm your new password"
              value={confirmPassword}
              onChange={(e) =>
                setConfirmPassword(e.target.value)
              }
              required
            />

            <button
              type="button"
              className="password-toggle"
              onClick={() =>
                setShowConfirmPassword(
                  !showConfirmPassword
                )
              }
              aria-label={
                showConfirmPassword
                  ? "Hide password"
                  : "Show password"
              }
            >
              {showConfirmPassword ? "🙈" : "👁️"}
            </button>
          </div>

          {/* Match Message */}
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

          {/* Submit */}
          <button
            type="submit"
            className="auth-button"
            disabled={
              loading ||
              !isPasswordStrong ||
              !passwordsMatch
            }
          >
            {loading
              ? "Resetting Password..."
              : "Reset Password"}
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

export default ResetPassword;