// Build kino-mcp and put it where Tauri looks for a sidecar.
//
// Tauri wants `src-tauri/binaries/kino-mcp-<target triple>` and strips the
// triple when it installs the file, so users get a plain `kino-mcp` next to
// the app. The sidecar is only declared in tauri.bundle-mcp.conf.json, which
// `npm run bundle` and the release workflow pass to `tauri build`: declaring
// it in tauri.conf.json would make every `cargo build`, test and `tauri dev`
// fail until this script had run - including the build of kino-mcp itself.
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, statSync } from "node:fs";
import { join } from "node:path";

const manifest = join("src-tauri", "Cargo.toml");
execFileSync("cargo", ["build", "--release", "--manifest-path", manifest, "--bin", "kino-mcp"], {
  stdio: "inherit",
});

const host = execFileSync("rustc", ["-vV"], { encoding: "utf8" })
  .split("\n")
  .find((l) => l.startsWith("host: "))
  ?.slice("host: ".length)
  .trim();
if (!host) throw new Error("rustc -vV did not report a host triple");

const ext = process.platform === "win32" ? ".exe" : "";
const src = join("src-tauri", "target", "release", `kino-mcp${ext}`);
const dir = join("src-tauri", "binaries");
const dest = join(dir, `kino-mcp-${host}${ext}`);
mkdirSync(dir, { recursive: true });
copyFileSync(src, dest);
console.log(`staged ${dest} (${statSync(dest).size} bytes)`);
