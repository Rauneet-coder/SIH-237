"use client";
import { ArrowUpRight, LogOut, Moon, Sun } from "lucide-react";
import { useAuth } from "../lib/authContext";
import { useTheme } from "./ThemeProvider";
export function Header({
  title,
  onSignIn,
}: {
  title: string;
  onSignIn: () => void;
}) {
  const { dark, toggle } = useTheme();
  const { user, logout } = useAuth();
  return (
    <header className="workspace-header">
      <div className="breadcrumb">
        Workspace <span>/</span> <strong>{title}</strong>
      </div>
      <div className="header-right">
        <button
          className="theme-toggle"
          role="switch"
          aria-checked={dark}
          aria-label="Dark mode"
          onClick={toggle}
          title={dark ? "Switch to light mode" : "Switch to dark mode"}
        >
          <Sun size={14} />
          <span className="theme-track">
            <span />
          </span>
          <Moon size={14} />
        </button>
        <span className="project-tag">SIH 26237</span>
        {user ? (
          <>
            <span className="profile-avatar">
              {user.username.slice(0, 2).toUpperCase()}
            </span>
            <span className="profile-name">{user.username}</span>
            <button
              className="icon-button"
              onClick={logout}
              aria-label="Sign out"
            >
              <LogOut size={17} />
            </button>
          </>
        ) : (
          <button className="header-login" onClick={onSignIn}>
            Sign in to workspace <ArrowUpRight size={15} />
          </button>
        )}
      </div>
    </header>
  );
}
