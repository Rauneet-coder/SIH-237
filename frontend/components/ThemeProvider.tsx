"use client";
import { createContext, useContext, useEffect, useState } from "react";
const ThemeContext = createContext({ dark: false, toggle: () => {} });
export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [dark, setDark] = useState(false);
  useEffect(() => {
    const sync = () =>
      setDark(document.documentElement.dataset.theme === "dark");
    sync();
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const update = () => {
      let saved: string | null = null;
      try {
        saved = localStorage.getItem("pramaan-theme");
      } catch {}
      if (saved !== "dark" && saved !== "light") {
        document.documentElement.dataset.theme = media.matches
          ? "dark"
          : "light";
        sync();
      }
    };
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  const toggle = () => {
    const next = !dark;
    document.documentElement.dataset.theme = next ? "dark" : "light";
    try {
      localStorage.setItem("pramaan-theme", next ? "dark" : "light");
    } catch {}
    setDark(next);
  };
  return (
    <ThemeContext.Provider value={{ dark, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}
export const useTheme = () => useContext(ThemeContext);
