import type { Terminal } from "@xterm/xterm";
import type { TermTheme } from "./themes";
import type { ImageExportOptions } from "./store";

/**
 * Render a terminal selection to a PNG.
 *
 * `term.getSelection()` returns plain text and nothing else - no colour, no
 * bold, no inverse. An image built from it would be a screenshot of a quote,
 * which is the one thing a screenshot already does better. So this walks the
 * buffer cells instead and keeps what the selection actually looked like:
 * every SGR attribute xterm tracks, resolved against the live theme.
 */

export interface CaptureOptions {
  term: Terminal;
  theme: TermTheme;
  /** The terminal's font stack, so the image matches what's on screen. */
  fontFamily: string;
  /** Host or tab name, printed in the caption. */
  title: string;
  /** Accent used for the caption rule; the theme's UI accent. */
  accent: string;
  /** Frame, caption and background choices; see Settings → Appearance. */
  options: ImageExportOptions;
}

interface Cell {
  chars: string;
  fg: string;
  bg: string;
  bold: boolean;
  italic: boolean;
  underline: boolean;
  strike: boolean;
  /** Columns this cell occupies: 2 for full-width glyphs, 0 for their tail. */
  width: number;
}

const FONT_SIZE = 14;
const LINE_HEIGHT = 1.35;
const PAD_X = 26;
const PAD_Y = 20;
const CAPTION_H = 30;
/** Height of the title bar on the `window` frame. */
const TITLEBAR_H = 34;
/** Breathing room around the capture when a background wash is on. */
const WASH = 22;
/** Drawn at 2x so the PNG stays sharp when pasted into a chat that scales it. */
const SCALE = 2;

/** The 6x6x6 cube and grey ramp that make up xterm's 256-colour palette. */
function paletteColor(index: number, theme: TermTheme): string {
  const named = [
    theme.black, theme.red, theme.green, theme.yellow,
    theme.blue, theme.magenta, theme.cyan, theme.white,
    theme.brightBlack, theme.brightRed, theme.brightGreen, theme.brightYellow,
    theme.brightBlue, theme.brightMagenta, theme.brightCyan, theme.brightWhite,
  ];
  if (index < 16) return named[index] ?? theme.foreground;
  if (index < 232) {
    const n = index - 16;
    const step = (v: number) => (v === 0 ? 0 : 55 + v * 40);
    const r = step(Math.floor(n / 36) % 6);
    const g = step(Math.floor(n / 6) % 6);
    const b = step(n % 6);
    return `rgb(${r},${g},${b})`;
  }
  const level = 8 + (index - 232) * 10;
  return `rgb(${level},${level},${level})`;
}

function rgbColor(value: number): string {
  return `rgb(${(value >> 16) & 0xff},${(value >> 8) & 0xff},${value & 0xff})`;
}

/**
 * Blend two colours without `color-mix()`.
 *
 * An unparseable value assigned to `ctx.fillStyle` is ignored - the canvas keeps
 * whatever colour it had - so a CSS function this WebKit doesn't know wouldn't
 * throw, it would quietly paint the wrong thing. Hex and `rgb()` are all this
 * module ever produces, so mixing them here is both safe and exact.
 */
function parseColor(color: string): [number, number, number] {
  const hex = color.trim();
  if (hex.startsWith("#")) {
    const body =
      hex.length === 4
        ? hex.slice(1).split("").map((c) => c + c).join("")
        : hex.slice(1, 7);
    const n = parseInt(body, 16);
    return [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
  }
  const nums = hex.match(/\d+/g);
  return nums && nums.length >= 3
    ? [Number(nums[0]), Number(nums[1]), Number(nums[2])]
    : [0, 0, 0];
}

/** `amount` is how much of `a` survives. */
function mix(a: string, b: string, amount: number): string {
  const [r1, g1, b1] = parseColor(a);
  const [r2, g2, b2] = parseColor(b);
  const at = (x: number, y: number) => Math.round(x * amount + y * (1 - amount));
  return `rgb(${at(r1, r2)},${at(g1, g2)},${at(b1, b2)})`;
}

/**
 * Read one buffer row into cells, resolving every colour to something canvas
 * can paint. `inverse` is applied here rather than at draw time so the rest of
 * the pipeline never has to think about it again.
 */
function readRow(
  term: Terminal,
  y: number,
  fromX: number,
  toX: number,
  theme: TermTheme
): Cell[] {
  const line = term.buffer.active.getLine(y);
  if (!line) return [];
  const out: Cell[] = [];
  for (let x = fromX; x < toX; x++) {
    const cell = line.getCell(x);
    if (!cell) continue;
    const width = cell.getWidth();
    // Width 0 is the second half of a full-width glyph; it carries no character.
    if (width === 0) continue;

    let fg = cell.isFgDefault()
      ? theme.foreground
      : cell.isFgRGB()
        ? rgbColor(cell.getFgColor())
        : paletteColor(cell.getFgColor(), theme);
    let bg = cell.isBgDefault()
      ? theme.background
      : cell.isBgRGB()
        ? rgbColor(cell.getBgColor())
        : paletteColor(cell.getBgColor(), theme);

    if (cell.isInverse()) [fg, bg] = [bg, fg];
    // Dim has no colour of its own; it's the foreground pulled toward the paper.
    if (cell.isDim()) fg = mix(fg, bg, 0.55);

    out.push({
      chars: cell.getChars() || " ",
      fg,
      bg,
      bold: !!cell.isBold(),
      italic: !!cell.isItalic(),
      underline: !!cell.isUnderline(),
      strike: !!cell.isStrikethrough(),
      width,
    });
  }
  return out;
}

/** Drop trailing cells that carry nothing, so the image is as wide as the
 *  content rather than as wide as the terminal. */
function trimEnd(cells: Cell[], background: string): Cell[] {
  let end = cells.length;
  while (end > 0) {
    const c = cells[end - 1];
    if (c.chars.trim() !== "" || c.bg !== background) break;
    end--;
  }
  return cells.slice(0, end);
}

/** The selected rows, in buffer coordinates, clipped to the selection ends. */
function selectedRows(term: Terminal, theme: TermTheme): Cell[][] | null {
  const range = term.getSelectionPosition();
  if (!range) return null;
  const rows: Cell[][] = [];
  for (let y = range.start.y; y <= range.end.y; y++) {
    const fromX = y === range.start.y ? range.start.x : 0;
    const toX = y === range.end.y ? range.end.x : term.cols;
    rows.push(trimEnd(readRow(term, y, fromX, toX, theme), theme.background));
  }
  // A selection that ends exactly at a line start produces a trailing empty row.
  while (rows.length > 1 && rows[rows.length - 1].length === 0) rows.pop();
  return rows.length ? rows : null;
}

function cellFont(cell: Cell, family: string): string {
  const style = cell.italic ? "italic " : "";
  const weight = cell.bold ? "700 " : "400 ";
  return `${style}${weight}${FONT_SIZE}px ${family}`;
}

/**
 * Render the current selection to a PNG blob, or null if nothing is selected.
 *
 * Waits on `document.fonts.ready` first: canvas silently falls back to a default
 * face for a font that hasn't finished loading, and a proportional fallback
 * would break the grid the whole image depends on.
 */
export async function captureSelection(opts: CaptureOptions): Promise<Blob | null> {
  const { term, theme, fontFamily, title, accent, options } = opts;
  const rows = selectedRows(term, theme);
  if (!rows) return null;

  await document.fonts?.ready;

  const probe = document.createElement("canvas").getContext("2d");
  if (!probe) return null;
  probe.font = `400 ${FONT_SIZE}px ${fontFamily}`;
  const cellW = probe.measureText("M").width;
  const cellH = Math.round(FONT_SIZE * LINE_HEIGHT);

  const cols = rows.reduce(
    (max, row) => Math.max(max, row.reduce((n, c) => n + c.width, 0)),
    1
  );
  // What sits above the text: a caption, a title bar, or nothing.
  const caption =
    options.frame === "kino" && (options.showHost || options.showTimestamp) ? CAPTION_H : 0;
  const titlebar = options.frame === "window" ? TITLEBAR_H : 0;
  const padX = options.frame === "minimal" ? 14 : PAD_X;
  const padY = options.frame === "minimal" ? 12 : PAD_Y;
  // The wash is margin outside the capture, so it only enlarges the canvas.
  const wash = options.background ? WASH : 0;

  const width = Math.ceil(cols * cellW) + padX * 2 + wash * 2;
  const height = rows.length * cellH + padY * 2 + caption + titlebar + wash * 2;

  const canvas = document.createElement("canvas");
  canvas.width = Math.ceil(width * SCALE);
  canvas.height = Math.ceil(height * SCALE);
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  ctx.scale(SCALE, SCALE);
  ctx.textBaseline = "top";

  // An accent wash behind the capture, for pasting onto a light background
  // where a bare dark rectangle would float unanchored.
  if (wash) {
    const grad = ctx.createLinearGradient(0, 0, width, height);
    grad.addColorStop(0, mix(accent, theme.background, 0.55));
    grad.addColorStop(1, mix(theme.foreground, theme.background, 0.22));
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, width, height);
  }

  // Mat.
  ctx.fillStyle = theme.background;
  ctx.fillRect(wash, wash, width - wash * 2, height - wash * 2);

  // Local time, not UTC: this is a caption for a human, and an unlabelled ISO
  // string five hours out from the clock on their wall is worse than none.
  const d = new Date();
  const two = (n: number) => String(n).padStart(2, "0");
  const stamp =
    `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())} ` +
    `${two(d.getHours())}:${two(d.getMinutes())}`;

  if (options.frame === "kino") {
    // Caption: what this is and when, so a pasted image still says where it
    // came from a week later. Set in the same face as the terminal, quietly.
    if (caption) {
      ctx.font = `600 9px ${fontFamily}`;
      ctx.fillStyle = mix(theme.foreground, theme.background, 0.45);
      if (options.showHost) {
        ctx.fillText(title.toUpperCase(), wash + padX, wash + padY - 6);
      }
      if (options.showTimestamp) {
        const w = ctx.measureText(stamp).width;
        ctx.fillText(stamp, width - wash - padX - w, wash + padY - 6);
      }
      ctx.fillStyle = accent;
      ctx.fillRect(wash + padX, wash + padY + 8, width - (wash + padX) * 2, 1);
    }
    // The perforation rail from the app's own chrome, at a whisper. Bounded to
    // the text block so it reads as a film edge, not a runaway border.
    const railTop = wash + padY + caption;
    ctx.fillStyle = mix(theme.foreground, theme.background, 0.1);
    for (let y = railTop; y + 7 <= railTop + rows.length * cellH; y += 14) {
      ctx.fillRect(wash + 9, y, 5, 7);
    }
  } else if (options.frame === "window") {
    // A title bar with three dots - the shape everyone reads as "terminal
    // window" without imitating any one platform's chrome.
    ctx.fillStyle = mix(theme.foreground, theme.background, 0.08);
    ctx.fillRect(wash, wash, width - wash * 2, TITLEBAR_H);
    ctx.fillStyle = mix(theme.foreground, theme.background, 0.28);
    for (let i = 0; i < 3; i++) {
      ctx.beginPath();
      ctx.arc(wash + 18 + i * 15, wash + TITLEBAR_H / 2, 4.5, 0, Math.PI * 2);
      ctx.fill();
    }
    const bits = [
      options.showHost ? title : "",
      options.showTimestamp ? stamp : "",
    ].filter(Boolean);
    if (bits.length) {
      ctx.font = `600 10px ${fontFamily}`;
      ctx.fillStyle = mix(theme.foreground, theme.background, 0.5);
      const label = bits.join("  ·  ");
      const w = ctx.measureText(label).width;
      ctx.fillText(label, (width - w) / 2, wash + TITLEBAR_H / 2 - 5);
    }
  }

  const top = wash + padY + caption + titlebar;
  rows.forEach((row, r) => {
    const y = top + r * cellH;
    let x = wash + padX;

    // Backgrounds first, as runs: per-cell fills leave hairline seams between
    // adjacent cells of the same colour at fractional widths.
    let runStart = x;
    let runColor = row[0]?.bg;
    for (let i = 0; i <= row.length; i++) {
      const cell = row[i];
      if (!cell || cell.bg !== runColor) {
        if (runColor && runColor !== theme.background) {
          ctx.fillStyle = runColor;
          ctx.fillRect(runStart, y, x - runStart, cellH);
        }
        runStart = x;
        runColor = cell?.bg;
      }
      if (cell) x += cell.width * cellW;
    }

    x = wash + padX;
    for (const cell of row) {
      if (cell.chars !== " ") {
        ctx.font = cellFont(cell, fontFamily);
        ctx.fillStyle = cell.fg;
        ctx.fillText(cell.chars, x, y + (cellH - FONT_SIZE) / 2);
      }
      const w = cell.width * cellW;
      if (cell.underline) {
        ctx.fillStyle = cell.fg;
        ctx.fillRect(x, y + cellH - 3, w, 1);
      }
      if (cell.strike) {
        ctx.fillStyle = cell.fg;
        ctx.fillRect(x, y + cellH / 2, w, 1);
      }
      x += w;
    }
  });

  return new Promise((resolve) => canvas.toBlob((b) => resolve(b), "image/png"));
}

/** Bytes as base64, for handing a PNG to the Rust side to write. */
export async function blobToBase64(blob: Blob): Promise<string> {
  const buf = new Uint8Array(await blob.arrayBuffer());
  let binary = "";
  // Chunked: spreading a megabyte-long array into apply() blows the stack.
  for (let i = 0; i < buf.length; i += 0x8000) {
    binary += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}
