import { useState } from "react";
import { useNavigate } from "react-router-dom";

function Topbar({ onMenuClick }) {
  const navigate = useNavigate();

  const [showUserMenu, setShowUserMenu] = useState(false);

  const userData = sessionStorage.getItem("user");

  let user = null;

  try {
    user = userData ? JSON.parse(userData) : null;
  } catch {
    user = null;
  }

  const username = user?.username || "User";
  const email = user?.email || "";

  const handleLogout = () => {
    sessionStorage.removeItem("access_token");
    sessionStorage.removeItem("user");

    navigate("/login");
  };

  return (
    <header className="dashboard-topbar">

      {/* Mobile Menu */}
      <button
        type="button"
        className="mobile-menu-button"
        onClick={onMenuClick}
        aria-label="Open navigation"
      >
        ☰
      </button>


      {/* Page Branding */}
      <div className="topbar-brand">

        <div className="topbar-mobile-logo">
          🛡️
        </div>

        <div>
          <h1>Dashboard</h1>

          <p>
            Monitor your online safety
          </p>
        </div>

      </div>


      {/* Topbar Actions */}
      <div className="topbar-actions">

        {/* Real-Time Status */}
        <div className="realtime-status">
          <span className="realtime-dot">
            ●
          </span>

          <span>
            Protection Active
          </span>
        </div>


        {/* Notifications */}
        <button
          type="button"
          className="notification-button"
          aria-label="Notifications"
          title="Notifications"
        >
          🔔

          <span className="notification-badge">
            0
          </span>
        </button>


        {/* User Menu */}
        <div className="user-menu-wrapper">

          <button
            type="button"
            className="user-menu-button"
            onClick={() =>
              setShowUserMenu(!showUserMenu)
            }
            aria-expanded={showUserMenu}
          >

            <div className="user-avatar">
              {username.charAt(0).toUpperCase()}
            </div>

            <div className="user-info">

              <strong>
                {username}
              </strong>

              <span>
                {email}
              </span>

            </div>

            <span className="user-menu-arrow">
              ▾
            </span>

          </button>


          {/* Dropdown */}
          {showUserMenu && (
            <div className="user-dropdown">

              <div className="dropdown-user">

                <div className="user-avatar large">
                  {username.charAt(0).toUpperCase()}
                </div>

                <div>
                  <strong>
                    {username}
                  </strong>

                  <span>
                    {email}
                  </span>
                </div>

              </div>


              <div className="dropdown-divider" />


              <button
                type="button"
                onClick={() => {
                  setShowUserMenu(false);
                  navigate("/dashboard/profile");
                }}
              >
                👤 Profile
              </button>


              <button
                type="button"
                onClick={() => {
                  setShowUserMenu(false);
                  navigate("/dashboard/settings");
                }}
              >
                ⚙️ Settings
              </button>


              <div className="dropdown-divider" />


              <button
                type="button"
                className="dropdown-logout"
                onClick={handleLogout}
              >
                ↪ Logout
              </button>

            </div>
          )}

        </div>

      </div>

    </header>
  );
}

export default Topbar;