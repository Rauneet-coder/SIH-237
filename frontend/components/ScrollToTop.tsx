"use client";
import { useEffect, useState } from "react";
import { ArrowUp } from "lucide-react";
export function ScrollToTop() {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const update = () => setVisible(window.scrollY > 500);
    update();
    window.addEventListener("scroll", update, { passive: true });
    return () => window.removeEventListener("scroll", update);
  }, []);
  if (!visible) return null;
  return (
    <button
      className="scroll-to-top"
      aria-label="Back to top"
      title="Back to top"
      onClick={() => {
        window.scrollTo({
          top: 0,
          behavior: window.matchMedia("(prefers-reduced-motion: reduce)")
            .matches
            ? "auto"
            : "smooth",
        });
        document
          .getElementById("workspace-content")
          ?.focus({ preventScroll: true });
      }}
    >
      <ArrowUp size={18} />
    </button>
  );
}
