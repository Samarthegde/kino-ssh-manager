export interface TermTheme {
  background: string; foreground: string;
  cursor: string; cursorAccent: string;
  black: string; red: string; green: string; yellow: string;
  blue: string; magenta: string; cyan: string; white: string;
  brightBlack: string; brightRed: string; brightGreen: string; brightYellow: string;
  brightBlue: string; brightMagenta: string; brightCyan: string; brightWhite: string;
}

export interface Theme {
  id: string;
  name: string;
  dark: boolean;
  ui: {
    bg: string; surface: string; overlay: string;
    muted: string; subtle: string; text: string; subtext: string;
    blue: string; green: string; red: string; yellow: string; mauve: string;
    btnPrimaryFg: string;
  };
  term: TermTheme;
}

export const THEMES: Theme[] = [
  {
    id: "catppuccin-mocha",
    name: "Catppuccin Mocha",
    dark: true,
    ui: {
      bg: "#1e1e2e", surface: "#181825", overlay: "#313244",
      muted: "#45475a", subtle: "#6c7086", text: "#cdd6f4", subtext: "#a6adc8",
      blue: "#89b4fa", green: "#a6e3a1", red: "#f38ba8", yellow: "#f9e2af", mauve: "#cba6f7",
      btnPrimaryFg: "#1e1e2e",
    },
    term: {
      background: "#1e1e2e", foreground: "#cdd6f4",
      cursor: "#f5e0dc", cursorAccent: "#1e1e2e",
      black: "#45475a", red: "#f38ba8", green: "#a6e3a1", yellow: "#f9e2af",
      blue: "#89b4fa", magenta: "#f5c2e7", cyan: "#94e2d5", white: "#bac2de",
      brightBlack: "#585b70", brightRed: "#f38ba8", brightGreen: "#a6e3a1", brightYellow: "#f9e2af",
      brightBlue: "#89b4fa", brightMagenta: "#f5c2e7", brightCyan: "#94e2d5", brightWhite: "#a6adc8",
    },
  },
  {
    id: "catppuccin-latte",
    name: "Catppuccin Latte",
    dark: false,
    ui: {
      bg: "#eff1f5", surface: "#e6e9ef", overlay: "#ccd0da",
      muted: "#bcc0cc", subtle: "#9ca0b0", text: "#4c4f69", subtext: "#5c5f77",
      blue: "#1e66f5", green: "#40a02b", red: "#d20f39", yellow: "#df8e1d", mauve: "#8839ef",
      btnPrimaryFg: "#ffffff",
    },
    term: {
      background: "#eff1f5", foreground: "#4c4f69",
      cursor: "#dc8a78", cursorAccent: "#eff1f5",
      black: "#5c5f77", red: "#d20f39", green: "#40a02b", yellow: "#df8e1d",
      blue: "#1e66f5", magenta: "#ea76cb", cyan: "#179299", white: "#acb0be",
      brightBlack: "#6c6f85", brightRed: "#d20f39", brightGreen: "#40a02b", brightYellow: "#df8e1d",
      brightBlue: "#1e66f5", brightMagenta: "#ea76cb", brightCyan: "#179299", brightWhite: "#bcc0cc",
    },
  },
  {
    id: "dracula",
    name: "Dracula",
    dark: true,
    ui: {
      bg: "#282a36", surface: "#21222c", overlay: "#44475a",
      muted: "#373844", subtle: "#6272a4", text: "#f8f8f2", subtext: "#d8d8d2",
      blue: "#8be9fd", green: "#50fa7b", red: "#ff5555", yellow: "#ffb86c", mauve: "#bd93f9",
      btnPrimaryFg: "#282a36",
    },
    term: {
      background: "#282a36", foreground: "#f8f8f2",
      cursor: "#f8f8f0", cursorAccent: "#282a36",
      black: "#21222c", red: "#ff5555", green: "#50fa7b", yellow: "#f1fa8c",
      blue: "#bd93f9", magenta: "#ff79c6", cyan: "#8be9fd", white: "#f8f8f2",
      brightBlack: "#6272a4", brightRed: "#ff6e6e", brightGreen: "#69ff94", brightYellow: "#ffffa5",
      brightBlue: "#d6acff", brightMagenta: "#ff92df", brightCyan: "#a4ffff", brightWhite: "#ffffff",
    },
  },
  {
    id: "tokyo-night",
    name: "Tokyo Night",
    dark: true,
    ui: {
      bg: "#1a1b26", surface: "#16161e", overlay: "#292e42",
      muted: "#3b4261", subtle: "#565f89", text: "#c0caf5", subtext: "#9aa5ce",
      blue: "#7aa2f7", green: "#9ece6a", red: "#f7768e", yellow: "#e0af68", mauve: "#bb9af7",
      btnPrimaryFg: "#1a1b26",
    },
    term: {
      background: "#1a1b26", foreground: "#c0caf5",
      cursor: "#c0caf5", cursorAccent: "#1a1b26",
      black: "#15161e", red: "#f7768e", green: "#9ece6a", yellow: "#e0af68",
      blue: "#7aa2f7", magenta: "#bb9af7", cyan: "#7dcfff", white: "#acb0d0",
      brightBlack: "#414868", brightRed: "#f7768e", brightGreen: "#9ece6a", brightYellow: "#e0af68",
      brightBlue: "#7aa2f7", brightMagenta: "#bb9af7", brightCyan: "#7dcfff", brightWhite: "#c0caf5",
    },
  },
  {
    id: "nord",
    name: "Nord",
    dark: true,
    ui: {
      bg: "#2e3440", surface: "#3b4252", overlay: "#434c5e",
      muted: "#4c566a", subtle: "#616e88", text: "#eceff4", subtext: "#d8dee9",
      blue: "#81a1c1", green: "#a3be8c", red: "#bf616a", yellow: "#ebcb8b", mauve: "#b48ead",
      btnPrimaryFg: "#2e3440",
    },
    term: {
      background: "#2e3440", foreground: "#eceff4",
      cursor: "#d8dee9", cursorAccent: "#2e3440",
      black: "#3b4252", red: "#bf616a", green: "#a3be8c", yellow: "#ebcb8b",
      blue: "#81a1c1", magenta: "#b48ead", cyan: "#88c0d0", white: "#e5e9f0",
      brightBlack: "#4c566a", brightRed: "#bf616a", brightGreen: "#a3be8c", brightYellow: "#ebcb8b",
      brightBlue: "#81a1c1", brightMagenta: "#b48ead", brightCyan: "#8fbcbb", brightWhite: "#eceff4",
    },
  },
  {
    id: "gruvbox-dark",
    name: "Gruvbox Dark",
    dark: true,
    ui: {
      bg: "#282828", surface: "#1d2021", overlay: "#3c3836",
      muted: "#504945", subtle: "#665c54", text: "#ebdbb2", subtext: "#d5c4a1",
      blue: "#83a598", green: "#b8bb26", red: "#fb4934", yellow: "#fabd2f", mauve: "#d3869b",
      btnPrimaryFg: "#282828",
    },
    term: {
      background: "#282828", foreground: "#ebdbb2",
      cursor: "#fbf1c7", cursorAccent: "#282828",
      black: "#3c3836", red: "#cc241d", green: "#98971a", yellow: "#d79921",
      blue: "#458588", magenta: "#b16286", cyan: "#689d6a", white: "#a89984",
      brightBlack: "#928374", brightRed: "#fb4934", brightGreen: "#b8bb26", brightYellow: "#fabd2f",
      brightBlue: "#83a598", brightMagenta: "#d3869b", brightCyan: "#8ec07c", brightWhite: "#ebdbb2",
    },
  },
];

export function applyTheme(theme: Theme): void {
  const r = document.documentElement.style;
  const u = theme.ui;
  r.setProperty("--bg", u.bg);
  r.setProperty("--surface", u.surface);
  r.setProperty("--overlay", u.overlay);
  r.setProperty("--muted", u.muted);
  r.setProperty("--subtle", u.subtle);
  r.setProperty("--text", u.text);
  r.setProperty("--subtext", u.subtext);
  r.setProperty("--blue", u.blue);
  r.setProperty("--green", u.green);
  r.setProperty("--red", u.red);
  r.setProperty("--yellow", u.yellow);
  r.setProperty("--mauve", u.mauve);
  r.setProperty("--btn-primary-fg", u.btnPrimaryFg);
}
