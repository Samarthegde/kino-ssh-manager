import { useEffect, useRef, useState } from "react";
import { THEMES } from "../themes";
import { useVaultStore } from "../store";

export function ThemePicker() {
  const { theme: themeId, setTheme } = useVaultStore();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const active = THEMES.find((t) => t.id === themeId) ?? THEMES[0];

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  return (
    <div className="theme-wrap" ref={ref}>
      <button
        className="btn btn-sm theme-trigger"
        onClick={() => setOpen((v) => !v)}
        title="Change theme"
      >
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z" />
          <circle cx="8.5" cy="7.5" r="1.5" fill="currentColor" stroke="none" />
          <circle cx="15.5" cy="7.5" r="1.5" fill="currentColor" stroke="none" />
          <circle cx="6.5" cy="12.5" r="1.5" fill="currentColor" stroke="none" />
          <circle cx="17.5" cy="12.5" r="1.5" fill="currentColor" stroke="none" />
        </svg>
        {active.name}
      </button>

      {open && (
        <div className="theme-dropdown">
          <p className="theme-dropdown-title">Theme</p>
          {THEMES.map((t) => (
            <button
              key={t.id}
              className={`theme-option ${t.id === themeId ? "active" : ""}`}
              onClick={() => { setTheme(t.id); setOpen(false); }}
            >
              <div className="theme-swatches">
                <span className="swatch" style={{ background: t.ui.surface }} />
                <span className="swatch" style={{ background: t.ui.blue }} />
                <span className="swatch" style={{ background: t.ui.green }} />
                <span className="swatch" style={{ background: t.ui.red }} />
              </div>
              <span className="theme-option-name">
                {t.name}
                {!t.dark && <span className="theme-light-tag">light</span>}
              </span>
              {t.id === themeId && (
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
