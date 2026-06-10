import type { ReactNode } from "react";

/** Selectable OS tags. `value` is what we persist on the host. */
export const OS_OPTIONS: { value: string; label: string }[] = [
  { value: "linux", label: "Linux (generic)" },
  { value: "ubuntu", label: "Ubuntu" },
  { value: "debian", label: "Debian" },
  { value: "fedora", label: "Fedora" },
  { value: "arch", label: "Arch Linux" },
  { value: "alpine", label: "Alpine" },
  { value: "windows", label: "Windows" },
  { value: "macos", label: "macOS" },
  { value: "other", label: "Other / Unknown" },
];

// Monochrome icons drawn with currentColor so they tint with the host color.
const PATHS: Record<string, ReactNode> = {
  // Tux — simple penguin silhouette.
  linux: (
    <path
      fill="currentColor"
      d="M12 2c-1.9 0-3.1 1.6-3.1 3.6 0 .8.2 1.5.2 2.2 0 1-1.4 2.4-2.3 4.5-.8 1.9-1.3 3.3-2.1 4.4-.5.7-1.4 1.1-1.4 1.9 0 .6.6.9 1.3.7.5-.1.9-.5 1.1-.5.2 0 .2.3.2.7 0 .5.3.8 1 .8h8.2c.7 0 1-.3 1-.8 0-.4 0-.7.2-.7.2 0 .6.4 1.1.5.7.2 1.3-.1 1.3-.7 0-.8-.9-1.2-1.4-1.9-.8-1.1-1.3-2.5-2.1-4.4-.9-2.1-2.3-3.5-2.3-4.5 0-.7.2-1.4.2-2.2C15.1 3.6 13.9 2 12 2zm-1.4 4.1c.4 0 .7.4.7.9s-.3.9-.7.9-.7-.4-.7-.9.3-.9.7-.9zm2.8 0c.4 0 .7.4.7.9s-.3.9-.7.9-.7-.4-.7-.9.3-.9.7-.9zM12 8.7c.7 0 1.6.5 1.6 1 0 .3-.4.5-.8.7-.3.2-.6.5-.8.5s-.5-.3-.8-.5c-.4-.2-.8-.4-.8-.7 0-.5.9-1 1.4-1z"
    />
  ),
  // Ubuntu — circle of friends.
  ubuntu: (
    <>
      <circle cx="12" cy="12" r="8.2" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="12" cy="3.8" r="1.9" fill="currentColor" />
      <circle cx="4.9" cy="16" r="1.9" fill="currentColor" />
      <circle cx="19.1" cy="16" r="1.9" fill="currentColor" />
      <circle cx="12" cy="12" r="2.1" fill="currentColor" />
    </>
  ),
  // Debian — simplified swirl.
  debian: (
    <path
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      d="M15 5.2C10.6 4.2 6.5 7 5.6 11.4c-.8 3.9 1.6 7.7 5.5 8.6 3.2.7 6-1 6.6-3.8.5-2.4-.9-4.7-3.3-5.2-1.9-.4-3.6.7-4 2.4"
    />
  ),
  // Fedora — "f" inside a circle.
  fedora: (
    <>
      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <path
        fill="none"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        d="M14.3 8.3a2.3 2.3 0 0 0-3.9 1.6V16M9 12.2h4.2"
      />
    </>
  ),
  // Arch — stylized mountain "A".
  arch: (
    <path
      fill="currentColor"
      d="M12 2.5 4 19.5c1.9-1 3.3-1.9 4.2-3L12 8.6l3.8 7.9c.9 1.1 2.3 2 4.2 3L12 2.5z"
    />
  ),
  // Alpine — mountain peaks.
  alpine: (
    <path
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinejoin="round"
      d="M3 18.5 9 8l3.4 5.6L14.5 10l6.5 8.5z"
    />
  ),
  // Windows — four panes.
  windows: (
    <path
      fill="currentColor"
      d="M3 5.6 10.6 4.5v7H3V5.6zm8.6-1.2L21 3v8.5h-9.4V4.4zM3 12.6h7.6v7L3 18.4v-5.8zm8.6 0H21V21l-9.4-1.3v-7.1z"
    />
  ),
  // macOS — apple silhouette with leaf.
  macos: (
    <>
      <path
        fill="currentColor"
        d="M15.6 2.3c.1 1-.3 2-1 2.7-.7.8-1.7 1.3-2.7 1.2-.1-1 .4-2 1-2.7.7-.8 1.8-1.3 2.7-1.2z"
      />
      <path
        fill="currentColor"
        d="M18.9 16.4c-.4 1-.6 1.4-1.1 2.2-.8 1.2-1.9 2.7-3.2 2.7-1.2 0-1.5-.8-3.1-.8s-2 .8-3.1.8c-1.4 0-2.4-1.3-3.2-2.6C2.6 17.7 2.1 14.5 3.6 12.2c.9-1.4 2.3-2.3 3.7-2.3 1.4 0 2.2.8 3.4.8 1.1 0 1.8-.8 3.3-.8 1.3 0 2.6.7 3.5 1.8-3 1.7-2.6 6 .4 4.7z"
      />
    </>
  ),
  // Generic — server stack.
  other: (
    <>
      <rect x="4" y="4.5" width="16" height="6.5" rx="1.4" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <rect x="4" y="13" width="16" height="6.5" rx="1.4" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="7.4" cy="7.7" r="1" fill="currentColor" />
      <circle cx="7.4" cy="16.2" r="1" fill="currentColor" />
    </>
  ),
};

export function OsIcon({ os, size = 16 }: { os?: string | null; size?: number }) {
  const icon = (os && PATHS[os]) || PATHS.other;
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      {icon}
    </svg>
  );
}
