import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { THEMES, applyTheme } from "./themes";

// Apply saved theme before first render to avoid flash
const savedThemeId = localStorage.getItem("ssh-mgr:theme") ?? "catppuccin-mocha";
applyTheme(THEMES.find((t) => t.id === savedThemeId) ?? THEMES[0]);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
