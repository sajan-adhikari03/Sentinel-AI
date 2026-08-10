import { NavLink, useNavigate } from "react-router-dom";

function Sidebar({ isOpen, onClose }) {
  const navigate = useNavigate();

  const handleLogout = () => {
    sessionStorage.removeItem("access_token");
    sessionStorage.removeItem("user");

    navigate("/login");
  };

  const navItems = [
    {
      label: "Dashboard",
      icon: "⌂",
      path: "/dashboard",
    },
    {
      label: "URL Scanner",
      icon: "🔗",
      path: "/dashboard/url-scanner",
    },
    {
      label: "SMS Scanner",
      icon: "📱",
      path: "/dashboard/sms-scanner",
    },
    {
      label: "Email Scanner",
      icon: "📧",
      path: "/dashboard/email-scanner",
    },
    {
      label: "Fake Job Detector",
      icon: "💼",
      path: "/dashboard/fake-job",
    },
    {
      label: "Investment Detector",
      icon: "💰",
      path: "/dashboard/investment",
    },
    {
      label: "Screenshot Scanner",
      icon: "🖼️",
      path: "/dashboard/screenshot",
    },
    {
      label: "Scan History",
      icon: "📜",
      path: "/dashboard/history",
    },
    {
      label: "Awareness",
      icon: "🛡️",
      path: "/dashboard/awareness",
    },
  ];

  return (
    <>
      {isOpen && (
        <div
          className="sidebar-overlay"
          onClick={onClose}
        />
      )}

      <aside
        className={`dashboard-sidebar ${
          isOpen ? "sidebar-open" : ""
        }`}
      >
        <div className="sidebar-header">
          <NavLink
            to="/dashboard"
            className="sidebar-logo"
            onClick={onClose}
          >
            <span className="sidebar-logo-icon">
              🛡️
            </span>

            <div>
              <strong>Sentinel AI</strong>
              <small>Scam Protection</small>
            </div>
          </NavLink>

          <button
            type="button"
            className="sidebar-close"
            onClick={onClose}
            aria-label="Close navigation"
          >
            ×
          </button>
        </div>

        <div className="sidebar-section-title">
          MAIN
        </div>

        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === "/dashboard"}
              className={({ isActive }) =>
                `sidebar-nav-item ${
                  isActive ? "active" : ""
                }`
              }
              onClick={onClose}
            >
              <span className="sidebar-nav-icon">
                {item.icon}
              </span>

              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <NavLink
            to="/dashboard/profile"
            className={({ isActive }) =>
              `sidebar-nav-item ${
                isActive ? "active" : ""
              }`
            }
            onClick={onClose}
          >
            <span className="sidebar-nav-icon">
              👤
            </span>

            <span>Profile</span>
          </NavLink>

          <NavLink
            to="/dashboard/settings"
            className={({ isActive }) =>
              `sidebar-nav-item ${
                isActive ? "active" : ""
              }`
            }
            onClick={onClose}
          >
            <span className="sidebar-nav-icon">
              ⚙️
            </span>

            <span>Settings</span>
          </NavLink>

          <button
            type="button"
            className="sidebar-logout"
            onClick={handleLogout}
          >
            <span className="sidebar-nav-icon">
              ↪
            </span>

            <span>Logout</span>
          </button>
        </div>
      </aside>
    </>
  );
}

export default Sidebar;