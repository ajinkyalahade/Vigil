import type { ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { IconAlert, IconChart, IconDashboard, IconScan, IconSettings, IconShield } from "./Icons";

const PAGE_TITLES: Record<string, string> = {
  "/":          "Overview",
  "/scans":     "Scans",
  "/findings":  "Findings",
  "/analytics": "Analytics",
  "/settings":  "Settings",
};

export default function Layout({ children }: { children: ReactNode }) {
  const location = useLocation();
  const title = PAGE_TITLES[location.pathname] ?? "Vigil";

  return (
    <div className="appShell">
      {/* ── Slim icon sidebar ── */}
      <aside className="sidebar">
        <div className="brandMark" aria-hidden>
          <IconShield size={20} />
        </div>
        <nav className="nav">
          <NavLink to="/" end title="Overview">
            <IconDashboard className="navIcon" />
          </NavLink>
          <NavLink to="/scans" title="Scans">
            <IconScan className="navIcon" />
          </NavLink>
          <NavLink to="/findings" title="Findings">
            <IconAlert className="navIcon" />
          </NavLink>
          <NavLink to="/analytics" title="Analytics">
            <IconChart className="navIcon" />
          </NavLink>
          <NavLink to="/settings" title="Settings">
            <IconSettings className="navIcon" />
          </NavLink>
        </nav>
        <div className="sidebarSpacer" />
      </aside>

      {/* ── Main area ── */}
      <div className="mainWrapper">
        {/* Topbar */}
        <header className="topbar">
          <div className="topbarTitle">{title}</div>

          {/* Search */}
          <div className="searchBar">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden>
              <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="2" />
              <path d="m21 21-4.35-4.35" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
            <input placeholder="Search…" />
          </div>

          {/* Right actions */}
          <div className="topbarRight">
            <button className="topbarIconBtn" aria-label="Notifications">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                <path d="M18 16H6l1-1v-5a5 5 0 0110 0v5l1 1z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
                <path d="M12 22a2.2 2.2 0 002-2H10a2.2 2.2 0 002 2z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
              </svg>
            </button>
            <div className="userChip">
              <div className="userAvatar">VG</div>
              <span className="userName">Admin</span>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="content">{children}</main>
      </div>
    </div>
  );
}
