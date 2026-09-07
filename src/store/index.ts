import { invoke } from "@tauri-apps/api/core";
import { create } from "zustand";
import { clearTerminalOutput } from "../terminalBuffer";
import { forEachTerminal } from "../terminalRegistry";
import { DEFAULT_KEYBINDINGS, KeyActionId } from "../keymap";
import { THEMES } from "../themes";

export type DefaultAuth = "Password" | "SshKey" | "Agent";

export type ProxyType = "socks5" | "http";

export type ForwardKind = "local" | "socks" | "remote";

export interface PortForward {
  id: string;
  label: string;
  /** "local" (ssh -L), "socks" (ssh -D), or "remote" (ssh -R). Defaults to local. */
  kind?: ForwardKind;
  local_port: number;
  remote_host: string;
  remote_port: number;
  /** Remote forwards: the address the server binds on (default 127.0.0.1). */
  bind_host?: string;
}

export interface Host {
  id: string;
  name: string;
  hostname: string;
  port: number;
  username: string;
  default_auth: DefaultAuth;
  password?: string | null;
  private_key?: string | null;
  public_key?: string | null;
  passphrase?: string | null;
  port_forwards?: PortForward[];
  on_connect_snippets?: string[];
  color?: string | null;
  notes?: string | null;
  group?: string | null;
  os?: string | null;
  connection_mode?: string | null;
  agent_id?: string | null;
  relay_url?: string | null;
  /** Bearer token for the relay, when it requires auth. */
  relay_token?: string | null;
  /** kino-control URL; when set the relay is discovered instead of fixed. */
  control_url?: string | null;
  /** Optional proxy to dial the host through: "socks5" or "http". */
  proxy_type?: ProxyType | string | null;
  proxy_host?: string | null;
  proxy_port?: number | null;
  proxy_username?: string | null;
  proxy_password?: string | null;
  /** Id of another vault host to tunnel through (SSH ProxyJump / bastion). */
  jump_host?: string | null;
  /** Resolved jump host, attached only at connect time (never persisted). */
  jump?: Host | null;
  /** Unix seconds when this key was generated or last rotated; null if unknown. */
  key_added_at?: number | null;
  /** Topic URL for ntfy.sh (or similar) to receive heartbeat failure notifications. */
  ntfy_topic?: string | null;
  /** "production" | "staging" | "development". Separate from `color`, which is
   *  decoration - a colour that means "this can take the site down" depends on
   *  the theme to be understood. */
  environment?: string | null;
}

export interface Note {
  id: string;
  title: string;
  body: string;
  /** Unix seconds; stamped by the backend on every save. */
  updated_at: number;
}

export interface Snippet {
  id: string;
  name: string;
  commands: string;
}

export interface SftpEntry {
  name: string;
  path: string;
  is_dir: boolean;
  size: number;
  perm: number;
}

export interface DockerContainer {
  id: string;
  name: string;
  image: string;
  status: string;
  state: string;
  ports: string;
}

export type DockerAction = "start" | "stop" | "restart" | "pause" | "unpause" | "remove";

export interface DockerImage {
  id: string;
  repo_tag: string;
  size: string;
}

export interface DockerVolume {
  name: string;
  driver: string;
}

export interface DockerNetwork {
  id: string;
  name: string;
  driver: string;
}

export interface UpdateInfo {
  current: string;
  latest: string;
  available: boolean;
  url: string;
}

export interface DiskInfo {
  mount: string;
  used_kb: number;
  total_kb: number;
}

export interface MetricsSnapshot {
  cpu_percent: number;
  mem_used_kb: number;
  mem_total_kb: number;
  net_rx_bytes_per_sec: number;
  net_tx_bytes_per_sec: number;
  load1: number;
  load5: number;
  load15: number;
  uptime_secs: number;
  disks: DiskInfo[] | null;
}

export interface RecordingInfo {
  name: string;
  size: number;
  created: number;
}

export interface ProcessInfo {
  pid: number;
  ppid: number;
  cpu: number;
  mem: number;
  rss_kb: number;
  user: string;
  state: string;
  command: string;
}

export type KillSignal = "TERM" | "KILL" | "HUP" | "INT" | "STOP" | "CONT";

export interface CronJob {
  /** Index into `CronTable.lines`; edits target this one line. */
  line: number;
  /** Five fields, or an `@nickname`. */
  schedule: string;
  command: string;
  /** False when the line is commented out - the usual way to park a job. */
  enabled: boolean;
  /** The `#` comment block above the job, if any. */
  comment: string | null;
  /** Plain English, e.g. "Every Tuesday at 04:00". */
  description: string;
  /** Unix seconds of the next few runs; empty for @reboot. */
  next_runs: number[];
}

export interface CronTable {
  /** Every line of the crontab, verbatim. Edits rewrite lines, never the file. */
  lines: string[];
  jobs: CronJob[];
  /** `NAME=value` lines, shown read-only for context. */
  env: string[];
  /** Compare-and-swap token; hand it back to `cronSave`. */
  token: string;
  /** The host's clock when this was read, in Unix seconds. */
  host_now: number;
  /** The host's UTC offset in minutes - cron fires on host local time. */
  host_offset_min: number;
  /** True when the user has no crontab yet. */
  empty: boolean;
}

export interface CronPreview {
  valid: boolean;
  description: string;
  next_runs: number[];
}

/** What a command line matched in the danger list, and what it does. */
export interface DangerMatch {
  matched: string;
  explains: string;
}

export interface AuditFinding {
  /** Stable id: "weak-rsa", "reused-key", "stale-key", … */
  id: string;
  severity: "high" | "medium" | "low";
  title: string;
  detail: string;
}

export interface KeyFacts {
  algorithm: string;
  /** Only meaningful for RSA/DSA. */
  bits: number | null;
  fingerprint: string;
  encrypted: boolean;
}

export interface HostAudit {
  host_id: string;
  host_name: string;
  auth: string;
  /** Null when the host has no key, or one that couldn't be read. */
  key: KeyFacts | null;
  key_added_at: number | null;
  /** Names of the other hosts sharing this key. */
  shared_with: string[];
  findings: AuditFinding[];
}

/** What a server said it can do. Mirrors `Offered` in algo_probe.rs. */
export interface SshOffered {
  banner: string;
  kex: string[];
  host_key: string[];
  cipher: string[];
  mac: string[];
  compression: string[];
}

export interface SshFinding {
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  remediation: string;
}

/** How good the negotiated set would be. */
export type SshGrade = "pq" | "classical" | "weak";

export interface SshAssessment {
  grade: SshGrade;
  kex: string | null;
  host_key: string | null;
  cipher: string | null;
  mac: string | null;
  findings: SshFinding[];
}

export interface HostProbe {
  id: string;
  /** "ok" | "unknown" (not probed, and why) | "unreachable" */
  status: string;
  offered: SshOffered | null;
  assessment: SshAssessment | null;
  detail: string | null;
  checked_at: number;
}

/** A private key found on this machine. Mirrors `KeyOnDisk`. */
export interface KeyOnDisk {
  path: string;
  /** "openssh" | "pem" | "pkcs8" | "ppk" */
  format: string;
  /** `null` for formats that cannot be read without a converter, e.g. PPK. */
  algorithm: string | null;
  bits: number | null;
  fingerprint: string | null;
  encrypted: boolean;
  comment: string | null;
  /** Unix permission bits. `null` on Windows, where the model is an ACL. */
  mode: number | null;
  modified: number | null;
  findings: AuditFinding[];
}

export interface ImportOutcome {
  host_id: string;
  host_name: string;
  fingerprint: string;
  /** The key was read back out of the saved vault file, not just added on
   *  screen. Removal from disk is refused until this is true. */
  verified_in_saved_vault: boolean;
}

export interface SweepReport {
  keys: KeyOnDisk[];
  /** The directories that were looked at, so the scope is visible. */
  scanned: string[];
  /** Problems that are not about one key, e.g. global agent forwarding. */
  findings: AuditFinding[];
  critical: number;
  high: number;
}

export interface AuditReport {
  hosts: HostAudit[];
  generated_at: number;
  high: number;
  medium: number;
  low: number;
}

export interface RotateOutcome {
  fingerprint: string;
  /** False when the old key couldn't be identified or removed. */
  old_key_removed: boolean;
  note: string | null;
}

export type AiProvider = "openrouter";

export interface CloudConfigView {
  control_url: string;
  key_set: boolean;
}

export interface CloudConfigInput {
  control_url: string;
  /** Empty keeps the stored key (it is never echoed back to the UI). */
  account_key: string;
}

/** How much of an exposed host an assistant may reach. Mirrors `McpMode`. */
export type McpMode = "read_only" | "guarded" | "full";

/** Mirrors `HostPolicyView` - the form the editor works in. */
export interface McpHostPolicy {
  mode: McpMode;
  rules_text: string;
}

/** Mirrors `McpBinaryCheck`. `matches` is null unless both halves are known. */
export interface McpBinaryCheck {
  asset: string;
  expected: string | null;
  path: string | null;
  actual: string | null;
  matches: boolean | null;
  detail: string | null;
}

/** Mirrors `McpConfigView` in mcp_config.rs. Carries no secrets. */
export interface McpConfig {
  /** Ids of the hosts the MCP server is allowed to reach. */
  exposed_host_ids: string[];
  /** Per-host access policy, keyed by host id. No entry means read-only. */
  host_policies: Record<string, McpHostPolicy>;
  /** The global rule block, in the text form the editor uses. */
  global_rules_text: string;
  /** True once an MCP password has been set. */
  configured: boolean;
  /** Absolute path of the exposed vault, shown so it can be backed up or removed. */
  mcp_vault_path: string;
  /** Name of the headless binary to point an MCP client at. */
  binary_hint: string;
}

export interface CloudMachine {
  agent_id: string;
  name: string;
  created_at: number;
  relay_url?: string | null;
  last_seen?: number | null;
}

export interface CloudAddedMachine {
  agent_id: string;
  name: string;
  install_command: string;
}

export interface AiConfigView {
  configured: boolean;
  provider: AiProvider;
  model: string;
  effort: string;
  has_api_key: boolean;
}

export interface AiConfigInput {
  provider: AiProvider;
  /** Empty means "keep the stored key". */
  api_key?: string;
  model?: string;
  effort?: string;
}

export type HostHealthStatus = "up" | "down" | "unknown";

export interface HostHealth {
  id: string;
  status: HostHealthStatus;
  /** TCP round-trip in ms; present only when up. */
  latency_ms?: number | null;
  /** Why it's down, or why it wasn't probed. */
  detail?: string | null;
}

export interface AiModelInfo {
  id: string;
  label: string;
}

export interface AiMessage {
  role: "user" | "assistant";
  content: string;
}

/** One kind of secret the backend kept out of a request, and how many. Carries
 *  no sample of what matched - showing it would put the secret back on screen. */
export interface RedactionHit {
  kind: string;
  count: number;
}

/** Exactly what a send would transmit, redaction already applied. */
export interface AiPreview {
  /** UTF-8 bytes of prompt text: the system message plus every turn. */
  bytes: number;
  system: string;
  messages: AiMessage[];
  redacted: RedactionHit[];
}

export type HostKeyVerdict =
  | { status: "trusted" }
  | { status: "new"; fingerprint: string }
  | { status: "changed"; fingerprint: string; known: string };

export type TabKind = "ssh" | "local";

export interface Tab {
  id: string;
  sessionId: string;
  kind: TabKind;
  host?: Host;
  connected: boolean;
  paneId: string;
  /** Optional custom tab label (e.g. a container shell name). */
  title?: string;
}

export interface SshKeyPair {
  private_key: string;
  public_key: string;
}

export interface HistoryEvent {
  id: string;
  timestamp: number;
  event_type: string;
  message: string;
  host_id?: string | null;
}

export interface SyncConfigView {
  configured: boolean;
  provider: string;
  owner: string;
  repo: string;
  path: string;
  branch: string;
  has_token: boolean;
  last_synced_at?: number | null;
}

export interface SyncConfigInput {
  token: string;
  owner: string;
  repo: string;
  path?: string;
  branch?: string;
}

export type PushOutcome =
  | { kind: "pushed"; sha: string; synced_at: number }
  | { kind: "conflict" };

export type PullOutcome =
  | { kind: "pulled"; sha: string; synced_at: number; hosts: Host[] }
  | { kind: "up_to_date" }
  | { kind: "no_remote" };

interface VaultStore {
  unlocked: boolean;
  hosts: Host[];
  snippets: Snippet[];
  tabs: Tab[];
  panes: string[];
  activePaneId: string;
  /** Optional user-given name per pane id; falls back to "Pane N" when unset. */
  paneNames: Record<string, string>;
  activeTabIds: Record<string, string | null>;
  theme: string;
  idleLockMinutes: number;
  defaultRelayUrl: string;
  /** Feature flag - when false, all Kino Agent / relay UI is hidden. */
  relayEnabled: boolean;
  /** Feature flag - when false, all AI Copilot UI is hidden. */
  copilotEnabled: boolean;
  /** Resolved keyboard shortcuts (defaults merged with user overrides). */
  keybindings: Record<KeyActionId, string>;
  /** When true, open tabs/panes are remembered and rebuilt on unlock. */
  restoreSessionEnabled: boolean;
  /** Host ids pinned to the home panel (empty-pane landing view). */
  favoriteHostIds: string[];
  /** Latest reachability probe per host id. Empty until the first sweep. */
  hostHealth: Record<string, HostHealth>;
  /** Seconds between health sweeps; 0 disables the poll entirely. */
  healthIntervalSec: number;
  /** xterm scrollback lines kept per terminal. */
  scrollbackLines: number;
  /** Bundled monospace family used by terminals. */
  terminalFont: string;
  /** Hex background override for terminals; "" follows the active theme. */
  terminalBackground: string;
  imageExport: ImageExportOptions;
  /** Interface font family (the app chrome, not the terminal). */
  appFont: string;
  /** Colour recognised patterns in terminal output (see src/highlight.ts). */
  syntaxHighlight: boolean;
  /** Stop all motion and drop the expensive decorative paint. */
  liteMode: boolean;
  /** When true, dropped SSH sessions auto-reconnect with exponential backoff. */
  autoReconnect: boolean;
  /** When true, keystrokes in the focused terminal fan out to every visible pane. */
  broadcastInput: boolean;
  activeForwards: Set<string>;

  checkVaultExists: () => Promise<boolean>;
  setTheme: (id: string) => void;
  setIdleLockMinutes: (minutes: number) => void;
  setDefaultRelayUrl: (url: string) => void;
  setRelayEnabled: (on: boolean) => void;
  setCopilotEnabled: (on: boolean) => void;
  /** Rebind a shortcut. An empty combo clears the action's binding. */
  setKeybinding: (id: KeyActionId, combo: string) => void;
  /** Restore one action to its default combo. */
  resetKeybinding: (id: KeyActionId) => void;
  /** Restore every shortcut to its default. */
  resetAllKeybindings: () => void;
  setRestoreSessionEnabled: (on: boolean) => void;
  /** Rebuild the tabs/panes captured at the last lock (best-effort, tolerant of failures). */
  restoreLastSession: () => Promise<void>;
  /** Pin/unpin a host from the home panel. */
  toggleFavoriteHost: (id: string) => void;
  setHealthIntervalSec: (seconds: number) => void;
  setScrollbackLines: (lines: number) => void;
  setTerminalFont: (family: string) => void;
  setTerminalBackground: (hex: string) => void;
  setImageExport: (opts: Partial<ImageExportOptions>) => void;
  setAppFont: (family: string) => void;
  setSyntaxHighlight: (on: boolean) => void;
  setLiteMode: (on: boolean) => void;
  /** Probe every host once and merge the results into `hostHealth`. */
  checkHostsHealth: () => Promise<void>;
  setAutoReconnect: (on: boolean) => void;
  setBroadcastInput: (on: boolean) => void;
  /** Re-establish a dropped SSH tab in place (new session id, same tab). */
  reconnectTab: (tabId: string) => Promise<void>;
  /** Parse ~/.ssh/config and save any hosts not already present. Returns count added. */
  importSshConfig: () => Promise<number>;
  /** Write vault hosts into a managed block in ~/.ssh/config. Returns count written. */
  exportSshConfig: () => Promise<number>;
  /** Append a public key to the host's authorized_keys (idempotent). */
  installPublicKey: (host: Host, publicKey: string) => Promise<void>;
  processesList: (sessionId: string, local: boolean) => Promise<ProcessInfo[]>;
  processKill: (sessionId: string, local: boolean, pid: number, signal: KillSignal) => Promise<void>;
  cronList: (sessionId: string, local: boolean) => Promise<CronTable>;
  /**
   * Write the crontab back. `lines` is the whole file and `token` is the one
   * from the `CronTable` this edit started from - the backend refuses the write
   * if the crontab changed on the host in the meantime.
   */
  cronSave: (
    sessionId: string,
    local: boolean,
    lines: string[],
    token: string
  ) => Promise<CronTable>;
  /** Describe a schedule without touching the host; drives the live editor preview. */
  cronPreview: (
    schedule: string,
    hostNow: number,
    hostOffsetMin: number
  ) => Promise<CronPreview>;
  /** Inspect every stored key. Entirely local - no host is contacted. */
  /** Is this command line worth stopping for? Called once per Enter, and only
   *  in a session marked production. */
  checkCommandDanger: (line: string) => Promise<DangerMatch | null>;
  auditKeys: () => Promise<AuditReport>;
  /** Find private keys on this machine. Detection only - it reads and
   *  describes, and works with the vault locked. */
  sweepKeys: (extraDirs: string[]) => Promise<SweepReport>;
  /** Copy a key on disk into the vault. Resolves with proof it was read back
   *  out of the *saved* vault - removal is refused until that is true. */
  importKeyFromDisk: (
    path: string,
    hostId: string | null,
    name: string
  ) => Promise<ImportOutcome>;
  /** Overwrite and delete a key file. Every precondition is re-checked in the
   *  backend, so this can refuse even when the UI offered it. */
  evictKeyFromDisk: (path: string, overrideConfig: boolean) => Promise<string>;
  /** Write a vault key back out to a file, created private from the start.
   *  Refuses to overwrite anything, so it can never destroy a key. */
  exportKeyToDisk: (
    hostId: string,
    path: string,
    includePublic: boolean
  ) => Promise<string>;
  /** Ask each host what cryptography it would use. Opens no session and reads
   *  no credential, so it works with the vault locked. */
  probeHostAlgorithms: (hosts: Host[]) => Promise<HostProbe[]>;
  writeTextFile: (content: string, path: string) => Promise<void>;
  /**
   * Replace a host's key with a fresh ed25519 one. Progress arrives on
   * `rotate-<hostId>` as plain strings; see SecurityPanel.
   */
  rotateKey: (hostId: string) => Promise<RotateOutcome>;
  aiGetConfig: () => Promise<AiConfigView | null>;
  cloudGetConfig: () => Promise<CloudConfigView | null>;
  cloudSetConfig: (config: CloudConfigInput) => Promise<CloudConfigView>;
  cloudListMachines: () => Promise<CloudMachine[]>;
  cloudAddMachine: (name: string) => Promise<CloudAddedMachine>;
  cloudRemoveMachine: (agentId: string) => Promise<void>;
  aiSetConfig: (config: AiConfigInput) => Promise<AiConfigView>;
  aiListModels: () => Promise<AiModelInfo[]>;
  /** Streams the reply over `ai-delta-<requestId>` events; see CopilotPanel.
   *  Resolves with what redaction removed on the way out. `allowSecrets` is the
   *  per-send override; omitting it redacts, which is the safe default. */
  aiSend: (
    requestId: string,
    system: string,
    messages: AiMessage[],
    allowSecrets?: boolean
  ) => Promise<RedactionHit[]>;
  /** What a send would carry, without sending it. Reads nothing from the vault,
   *  so it is safe to call on every keystroke and works while locked. */
  aiPreview: (
    system: string,
    messages: AiMessage[],
    allowSecrets?: boolean
  ) => Promise<AiPreview>;
  aiCancel: (requestId: string) => Promise<void>;
  startForward: (sessionId: string, forward: PortForward, host: Host) => Promise<void>;
  stopForward: (sessionId: string, forwardId: string) => Promise<void>;
  unlock: (password: string) => Promise<void>;
  lock: () => void;
  saveHost: (host: Host) => Promise<Host>;
  deleteHost: (id: string) => Promise<void>;
  connectToHost: (host: Host) => Promise<string>;
  openLocalShell: () => Promise<void>;
  closeTab: (tabId: string) => void;
  setActiveTab: (tabId: string) => void;
  splitPane: (paneId: string) => void;
  closePane: (paneId: string) => void;
  setActivePane: (paneId: string) => void;
  /** Rename a pane; an empty/blank name clears it back to the default "Pane N". */
  renamePane: (paneId: string, name: string) => void;
  /** Move an open tab (and its live session) into an existing pane. */
  moveTabToPane: (tabId: string, targetPaneId: string) => void;
  /** Split a new pane off and move the tab into it in one step. */
  moveTabToNewSplit: (tabId: string) => void;
  markTabDisconnected: (sessionId: string) => void;
  generateSshKey: () => Promise<SshKeyPair>;
  loadKeyFile: (path: string) => Promise<string>;
  exportHost: (host: Host, path: string) => Promise<void>;
  exportHostEncrypted: (host: Host, path: string, password: string) => Promise<void>;
  exportSshKey: (content: string, path: string) => Promise<void>;
  importHostFromFile: (path: string) => Promise<Host>;
  profileIsEncrypted: (path: string) => Promise<boolean>;
  importHostEncrypted: (path: string, password: string) => Promise<Host>;
  getHistory: () => Promise<HistoryEvent[]>;
  /** Fetch from the host, merge into the stored archive, return the merged list. */
  fetchShellHistory: (sessionId: string, hostId: string) => Promise<string[]>;
  /** What's archived for a host, without contacting it. */
  getShellHistory: (hostId: string) => Promise<string[]>;
  clearShellHistory: (hostId: string) => Promise<void>;
  notes: Note[];
  refreshNotes: () => Promise<void>;
  saveNote: (note: Note) => Promise<Note>;
  deleteNote: (id: string) => Promise<void>;
  refreshSnippets: () => Promise<void>;
  saveSnippet: (snippet: Snippet) => Promise<Snippet>;
  deleteSnippet: (id: string) => Promise<void>;
  syncGetConfig: () => Promise<SyncConfigView | null>;
  syncSetConfig: (config: SyncConfigInput) => Promise<SyncConfigView>;
  syncTest: () => Promise<boolean>;
  syncPush: (force?: boolean) => Promise<PushOutcome>;
  syncPull: (password: string) => Promise<PullOutcome>;
  syncRestore: (config: SyncConfigInput, password: string) => Promise<Host[]>;
  sftpOpen: (sessionId: string, host: Host) => Promise<string>;
  sftpList: (sessionId: string, path: string) => Promise<SftpEntry[]>;
  sftpDownload: (sessionId: string, remote: string, local: string) => Promise<void>;
  sftpUpload: (sessionId: string, local: string, remote: string) => Promise<void>;
  sftpReadFile: (sessionId: string, path: string) => Promise<string>;
  sftpWriteFile: (sessionId: string, path: string, content: string) => Promise<void>;
  sftpRename: (sessionId: string, from: string, to: string) => Promise<void>;
  sftpDelete: (sessionId: string, path: string, isDir: boolean) => Promise<void>;
  sftpMkdir: (sessionId: string, path: string) => Promise<void>;
  sftpChmod: (sessionId: string, path: string, mode: number) => Promise<void>;
  sftpClose: (sessionId: string) => Promise<void>;
  dockerPs: (sessionId: string, local: boolean, all: boolean) => Promise<DockerContainer[]>;
  dockerAction: (sessionId: string, local: boolean, containerId: string, action: DockerAction) => Promise<void>;
  dockerLogs: (sessionId: string, local: boolean, containerId: string, tail: number) => Promise<string>;
  dockerShell: (sessionId: string, local: boolean, containerId: string, containerName: string) => Promise<void>;
  dockerImages: (sessionId: string, local: boolean) => Promise<DockerImage[]>;
  dockerVolumes: (sessionId: string, local: boolean) => Promise<DockerVolume[]>;
  dockerNetworks: (sessionId: string, local: boolean) => Promise<DockerNetwork[]>;
  dockerLogsStream: (sessionId: string, local: boolean, containerId: string, tail: number) => Promise<string>;
  dockerLogsStreamStop: (streamId: string) => Promise<void>;
  metricsStart: (sessionId: string, local: boolean) => Promise<string>;
  metricsStop: (streamId: string) => Promise<void>;
  updateInfo: UpdateInfo | null;
  checkForUpdate: () => Promise<void>;
  /** The minisign key id the updater verifies against, read from the running
   *  config so it cannot drift from the key that actually gates an install. */
  updaterKeyId: () => Promise<string | null>;
  /** What the kino-mcp on this PATH is, against what the release says it
   *  should be. Both halves can legitimately be unknown. */
  checkMcpBinary: () => Promise<McpBinaryCheck>;
  changeMasterPassword: (currentPassword: string, newPassword: string) => Promise<void>;
  verifyHostKey: (host: Host) => Promise<HostKeyVerdict>;
  trustHostKey: (host: Host, fingerprint: string) => Promise<void>;
  forgetHostKey: (host: Host) => Promise<void>;

  recordingSessions: Set<string>;
  startRecording: (sessionId: string, filename: string) => Promise<void>;
  stopRecording: (sessionId: string) => Promise<void>;
  listRecordings: () => Promise<RecordingInfo[]>;
  readRecording: (filename: string) => Promise<string>;
  deleteRecording: (filename: string) => Promise<void>;
  setRecordingState: (sessionId: string, isRecording: boolean) => void;

  mcpGetConfig: () => Promise<McpConfig>;
  mcpSetPassword: (password: string) => Promise<void>;
  mcpSetExposedHosts: (hostIds: string[]) => Promise<void>;
  /** Rules arrive as typed text; the backend parses them, so a bad pattern is
   *  refused here rather than silently matching nothing later. */
  mcpSetHostPolicy: (hostId: string, mode: McpMode, rulesText: string) => Promise<void>;
  mcpSetGlobalRules: (rulesText: string) => Promise<void>;
}

const AUTO_SYNC_KEY = "ssh-mgr:autosync";
export function isAutoSyncEnabled() {
  return localStorage.getItem(AUTO_SYNC_KEY) === "1";
}
export function setAutoSyncEnabled(on: boolean) {
  localStorage.setItem(AUTO_SYNC_KEY, on ? "1" : "0");
}

// Feature flag: Kino Agent / relay-server connection mode. Off by default (opt-in),
// but auto-enabled on unlock if the vault already contains agent hosts - otherwise
// an existing user's agent config would silently disappear from the UI.
const RELAY_FLAG_KEY = "ssh-mgr:relay-enabled";
function relayFlagWasSet() {
  return localStorage.getItem(RELAY_FLAG_KEY) !== null;
}
function initialRelayEnabled() {
  return localStorage.getItem(RELAY_FLAG_KEY) === "1";
}

// AI Copilot is likewise opt-in: hidden until the user turns it on in Settings.
const COPILOT_FLAG_KEY = "ssh-mgr:copilot-enabled";
function initialCopilotEnabled() {
  return localStorage.getItem(COPILOT_FLAG_KEY) === "1";
}

// Keyboard shortcuts: only user *overrides* are persisted (a diff from the
// defaults), so shipping new defaults later doesn't get frozen out by old
// stored maps. The resolved map merges defaults with those overrides.
const KEYBINDINGS_KEY = "ssh-mgr:keybindings";
function loadKeybindingOverrides(): Partial<Record<KeyActionId, string>> {
  try {
    return JSON.parse(localStorage.getItem(KEYBINDINGS_KEY) || "{}");
  } catch {
    return {};
  }
}
function saveKeybindingOverrides(o: Partial<Record<KeyActionId, string>>) {
  localStorage.setItem(KEYBINDINGS_KEY, JSON.stringify(o));
}
function resolveKeybindings(): Record<KeyActionId, string> {
  return { ...DEFAULT_KEYBINDINGS, ...loadKeybindingOverrides() };
}

// Hosts the user pinned to the home panel (the empty-pane landing view). Stored
// by id in localStorage; the id is meaningless without the encrypted vault.
const FAVORITES_KEY = "ssh-mgr:favorites";
function initialFavorites(): string[] {
  try {
    const v = JSON.parse(localStorage.getItem(FAVORITES_KEY) || "[]");
    return Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
  } catch {
    return [];
  }
}

// Host health polling is opt-in: each sweep opens a short-lived TCP connection
// to every host, which shows up in server logs. 0 means off.
const HEALTH_INTERVAL_KEY = "ssh-mgr:health-interval";
const SCROLLBACK_KEY = "ssh-mgr:scrollback";
/** Frame drawn around an exported terminal capture. */
export type ImageFrame = "kino" | "minimal" | "window";

export interface ImageExportOptions {
  frame: ImageFrame;
  /** Print the host name in the caption. */
  showHost: boolean;
  /** Print the local timestamp in the caption. */
  showTimestamp: boolean;
  /** A soft accent wash behind the capture, for pasting onto light backgrounds. */
  background: boolean;
}

export const DEFAULT_IMAGE_EXPORT: ImageExportOptions = {
  frame: "kino",
  showHost: true,
  showTimestamp: true,
  background: false,
};

/** Tolerant of a stored blob from an older version, or none at all. */
function loadImageExport(): ImageExportOptions {
  try {
    const raw = localStorage.getItem(IMG_EXPORT_KEY);
    if (!raw) return DEFAULT_IMAGE_EXPORT;
    const parsed = JSON.parse(raw) as Partial<ImageExportOptions>;
    const frame: ImageFrame =
      parsed.frame === "minimal" || parsed.frame === "window" ? parsed.frame : "kino";
    return {
      frame,
      showHost: parsed.showHost ?? true,
      showTimestamp: parsed.showTimestamp ?? true,
      background: parsed.background ?? false,
    };
  } catch {
    return DEFAULT_IMAGE_EXPORT;
  }
}

const TERM_FONT_KEY = "ssh-mgr:term-font";
const TERM_BG_KEY = "ssh-mgr:term-bg";
const IMG_EXPORT_KEY = "ssh-mgr:image-export";
const APP_FONT_KEY = "ssh-mgr:app-font";
const HIGHLIGHT_KEY = "ssh-mgr:syntax-highlight";
const LITE_KEY = "ssh-mgr:lite";

/**
 * Push the reduced-motion/effects flag at the document.
 *
 * A data attribute rather than a class so it reads the same way as
 * data-theme-dark, and so the whole switch is one CSS block keyed off :root.
 */
export function applyLiteMode(on: boolean): void {
  document.documentElement.dataset.lite = on ? "1" : "0";
}

/** Interface faces. The display face (Big Shoulders, used for the wordmark and
 *  slab headings) is deliberately not swappable - it *is* the Kino Projection
 *  identity. This picks the face used for everything you read in a sentence. */
export const APP_FONTS = [
  { id: "Chivo", label: "Chivo", note: "Default" },
  { id: "IBM Plex Sans", label: "IBM Plex Sans", note: "" },
  { id: "Atkinson Hyperlegible", label: "Atkinson Hyperlegible", note: "High legibility" },
  { id: "system", label: "System default", note: "" },
] as const;

export const DEFAULT_APP_FONT = "Chivo";

/** Push the choice at the CSS variable the whole interface reads from. */
export function applyAppFont(family: string): void {
  const stack =
    family === "system"
      ? 'system-ui, -apple-system, "Segoe UI", sans-serif'
      : `"${family}", "Chivo", ui-sans-serif, system-ui, sans-serif`;
  document.documentElement.style.setProperty("--font-sans", stack);
}

/** Families bundled under public/fonts and declared in index.css. Anything not
 *  on this list has no @font-face, so it would silently fall back. */
export const TERMINAL_FONTS = [
  "JetBrains Mono",
  "Fira Code",
  "IBM Plex Mono",
  "Source Code Pro",
  "Inconsolata",
  "Ubuntu Mono",
] as const;

export const DEFAULT_TERMINAL_FONT = "JetBrains Mono";

/** Always end the stack with a generic monospace: xterm assumes a fixed grid,
 *  and a proportional fallback would break alignment outright. */
export function terminalFontStack(family: string): string {
  return `"${family}", "JetBrains Mono", monospace`;
}

/** Lines of scrollback per terminal. xterm's own default is 1000; 5000 was
 *  hardcoded here before this became a setting, so it stays the default. */
export const DEFAULT_SCROLLBACK = 5000;
/** Smallest scrollback we will honour. Zero is deliberately not allowed: with
 *  no scrollback xterm reports `hasScrollback === false` and turns wheel events
 *  into cursor-key escapes instead of scrolling, so scrolling up cycles the
 *  shell's command history rather than showing earlier output. */
const MIN_SCROLLBACK = 100;

function initialScrollback(): number {
  const raw = localStorage.getItem(SCROLLBACK_KEY);
  // `Number(null)` is 0, not NaN - so an unset key has to be caught here rather
  // than by the numeric check below, or every install that never opened the
  // setting silently gets zero scrollback.
  if (raw === null || raw.trim() === "") return DEFAULT_SCROLLBACK;
  const n = Number(raw);
  return Number.isFinite(n) && n >= MIN_SCROLLBACK ? n : DEFAULT_SCROLLBACK;
}

function initialHealthInterval(): number {
  const n = Number(localStorage.getItem(HEALTH_INTERVAL_KEY));
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * Attach the resolved jump-host chain so the backend can tunnel through it. A
 * host references its bastion by id (`jump_host`); this walks the chain against
 * the vault and embeds each hop in `jump`. Cycles and dead references terminate
 * the chain safely. Returns a shallow copy - the stored host keeps only the id.
 */
function withResolvedJump(host: Host, all: Host[], seen: Set<string> = new Set()): Host {
  const jumpId = host.jump_host?.trim();
  if (!jumpId || seen.has(host.id)) return { ...host, jump: null };
  seen.add(host.id);
  const jumpHost = all.find((h) => h.id === jumpId);
  if (!jumpHost || seen.has(jumpHost.id)) return { ...host, jump: null };
  return { ...host, jump: withResolvedJump(jumpHost, all, seen) };
}

// Session restore: remember the open tabs/panes so unlocking can rebuild them.
// Only reconnectable tabs are stored (local shells and SSH tabs backed by a
// vault host); the layout references hosts by id, so nothing is meaningful
// without the (encrypted) vault. Opt-in via the setting below.
const RESTORE_FLAG_KEY = "ssh-mgr:restore-session";
const SESSION_KEY = "ssh-mgr:session";
function initialRestoreEnabled() {
  return localStorage.getItem(RESTORE_FLAG_KEY) === "1";
}

interface SessionTab {
  hostId?: string;
  kind: TabKind;
  paneId: string;
  title?: string;
  active: boolean;
}
interface SessionSnapshot {
  panes: string[];
  activePaneId: string;
  paneNames: Record<string, string>;
  tabs: SessionTab[];
}

function serializeSession(state: VaultStore): SessionSnapshot {
  return {
    panes: state.panes,
    activePaneId: state.activePaneId,
    paneNames: state.paneNames,
    tabs: state.tabs
      .filter((t) => t.kind === "local" || !!t.host?.id)
      .map((t) => ({
        hostId: t.host?.id,
        kind: t.kind,
        paneId: t.paneId,
        title: t.title,
        active: state.activeTabIds[t.paneId] === t.id,
      })),
  };
}

function loadSessionSnapshot(): SessionSnapshot | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const snap = JSON.parse(raw) as SessionSnapshot;
    return snap.tabs?.length ? snap : null;
  } catch {
    return null;
  }
}

// Captured at unlock, before `unlocked` flips true and the live snapshotter
// would overwrite the stored layout with the (empty) fresh state.
let stashedSnapshot: SessionSnapshot | null = null;
export function hasAgentHosts(hosts: Host[]) {
  return hosts.some((h) => h.connection_mode === "agent");
}
// Best-effort push after a vault change; silent on failure/conflict.
function autoPush() {
  if (isAutoSyncEnabled()) invoke("sync_push", { force: false }).catch(() => {});
}

export const useVaultStore = create<VaultStore>((set, get) => ({
  unlocked: false,
  hosts: [],
  snippets: [],
  notes: [],
  tabs: [],
  panes: ["default"],
  activePaneId: "default",
  paneNames: {},
  activeTabIds: { "default": null },
  theme: localStorage.getItem("ssh-mgr:theme") ?? "kino-projection",
  idleLockMinutes: Number(localStorage.getItem("ssh-mgr:idle-lock") ?? "0"),
  defaultRelayUrl: localStorage.getItem("ssh-mgr:relay-url") ?? "",
  relayEnabled: initialRelayEnabled(),
  copilotEnabled: initialCopilotEnabled(),
  keybindings: resolveKeybindings(),
  restoreSessionEnabled: initialRestoreEnabled(),
  favoriteHostIds: initialFavorites(),
  hostHealth: {},
  healthIntervalSec: initialHealthInterval(),
  scrollbackLines: initialScrollback(),
  terminalFont: localStorage.getItem(TERM_FONT_KEY) || DEFAULT_TERMINAL_FONT,
  terminalBackground: localStorage.getItem(TERM_BG_KEY) ?? "",
  imageExport: loadImageExport(),
  appFont: localStorage.getItem(APP_FONT_KEY) || DEFAULT_APP_FONT,
  // On unless explicitly turned off: it is display-only, heavily guarded, and a
  // feature nobody discovers is a feature that was not shipped.
  syntaxHighlight: localStorage.getItem(HIGHLIGHT_KEY) !== "0",
  // Off unless asked for. The OS "reduce motion" preference already stops the
  // animations on its own; this is the switch for wanting it cheaper as well.
  liteMode: localStorage.getItem(LITE_KEY) === "1",
  // Auto-reconnect defaults on; broadcast is a transient per-run toggle (off).
  autoReconnect: localStorage.getItem("ssh-mgr:auto-reconnect") !== "0",
  broadcastInput: false,
  activeForwards: new Set<string>(),
  recordingSessions: new Set<string>(),
  updateInfo: null,

  setTheme: (id) => {
    localStorage.setItem("ssh-mgr:theme", id);
    set({ theme: id });
  },

  setIdleLockMinutes: (minutes) => {
    localStorage.setItem("ssh-mgr:idle-lock", String(minutes));
    set({ idleLockMinutes: minutes });
  },
  
  setDefaultRelayUrl: (url) => {
    localStorage.setItem("ssh-mgr:relay-url", url);
    set({ defaultRelayUrl: url });
  },

  setRelayEnabled: (on) => {
    localStorage.setItem(RELAY_FLAG_KEY, on ? "1" : "0");
    set({ relayEnabled: on });
  },

  setCopilotEnabled: (on) => {
    localStorage.setItem(COPILOT_FLAG_KEY, on ? "1" : "0");
    set({ copilotEnabled: on });
  },

  setKeybinding: (id, combo) => {
    const overrides = loadKeybindingOverrides();
    // Store the override only when it differs from the default; otherwise drop
    // it so the action tracks future default changes.
    if (combo && combo !== DEFAULT_KEYBINDINGS[id]) overrides[id] = combo;
    else delete overrides[id];
    saveKeybindingOverrides(overrides);
    set({ keybindings: resolveKeybindings() });
  },

  resetKeybinding: (id) => {
    const overrides = loadKeybindingOverrides();
    delete overrides[id];
    saveKeybindingOverrides(overrides);
    set({ keybindings: resolveKeybindings() });
  },

  resetAllKeybindings: () => {
    localStorage.removeItem(KEYBINDINGS_KEY);
    set({ keybindings: { ...DEFAULT_KEYBINDINGS } });
  },

  setRestoreSessionEnabled: (on) => {
    localStorage.setItem(RESTORE_FLAG_KEY, on ? "1" : "0");
    // Turning it off drops the stored layout so nothing lingers on disk.
    if (!on) localStorage.removeItem(SESSION_KEY);
    set({ restoreSessionEnabled: on });
  },

  setScrollbackLines: (lines) => {
    const n = Math.max(MIN_SCROLLBACK, Math.min(200_000, Math.floor(lines) || DEFAULT_SCROLLBACK));
    localStorage.setItem(SCROLLBACK_KEY, String(n));
    set({ scrollbackLines: n });
    // Apply to terminals that are already open, so the change is visible
    // without reconnecting. Shrinking discards the oldest lines immediately.
    forEachTerminal((t) => { t.options.scrollback = n; });
  },

  setTerminalFont: (family) => {
    const f = (TERMINAL_FONTS as readonly string[]).includes(family) ? family : DEFAULT_TERMINAL_FONT;
    localStorage.setItem(TERM_FONT_KEY, f);
    set({ terminalFont: f });
    forEachTerminal((t) => { t.options.fontFamily = terminalFontStack(f); });
  },

  setImageExport: (opts) => {
    const next = { ...get().imageExport, ...opts };
    try {
      localStorage.setItem(IMG_EXPORT_KEY, JSON.stringify(next));
    } catch {
      // A preference that won't persist isn't worth failing a capture over.
    }
    set({ imageExport: next });
  },

  setTerminalBackground: (hex) => {
    // "" means "follow the theme"; anything else must be a hex colour, since it
    // goes straight into xterm's theme object.
    const v = /^#[0-9a-fA-F]{6}$/.test(hex) ? hex.toLowerCase() : "";
    localStorage.setItem(TERM_BG_KEY, v);
    set({ terminalBackground: v });
    const base = THEMES.find((t) => t.id === get().theme) ?? THEMES[0];
    forEachTerminal((t) => {
      t.options.theme = { ...base.term, background: v || base.term.background };
    });
  },

  setAppFont: (family) => {
    const f = (APP_FONTS as readonly { id: string }[]).some((a) => a.id === family)
      ? family
      : DEFAULT_APP_FONT;
    localStorage.setItem(APP_FONT_KEY, f);
    set({ appFont: f });
    applyAppFont(f);
  },

  setLiteMode: (on) => {
    localStorage.setItem(LITE_KEY, on ? "1" : "0");
    set({ liteMode: on });
    applyLiteMode(on);
  },

  setSyntaxHighlight: (on) => {
    localStorage.setItem(HIGHLIGHT_KEY, on ? "1" : "0");
    set({ syntaxHighlight: on });
  },

  setHealthIntervalSec: (seconds) => {
    localStorage.setItem(HEALTH_INTERVAL_KEY, String(seconds));
    // Turning the poll off clears stale dots rather than freezing them.
    set(seconds > 0 ? { healthIntervalSec: seconds } : { healthIntervalSec: 0, hostHealth: {} });
  },

  checkHostsHealth: async () => {
    const hosts = get().hosts;
    if (hosts.length === 0) return;
    try {
      const results = await invoke<HostHealth[]>("check_hosts_health", { hosts });
      set((state) => {
        const next = { ...state.hostHealth };
        for (const r of results) {
          const prev = next[r.id];
          if (prev && prev.status === "up" && r.status === "down") {
            const host = hosts.find(h => h.id === r.id);
            const hostName = host?.name || r.id;
            
            // 1. Desktop Notification
            import("@tauri-apps/plugin-notification").then(async ({ isPermissionGranted, requestPermission, sendNotification }) => {
              let permissionGranted = await isPermissionGranted();
              if (!permissionGranted) {
                const permission = await requestPermission();
                permissionGranted = permission === 'granted';
              }
              if (permissionGranted) {
                sendNotification({ title: 'Host Down', body: `Heartbeat flatlined for ${hostName}` });
              }
            }).catch(e => console.error("Notification plugin error:", e));

            // 2. Ntfy Webhook
            if (host?.ntfy_topic) {
              fetch(host.ntfy_topic, {
                method: "POST",
                body: `Heartbeat flatlined for ${hostName}`
              }).catch(e => console.error("Failed to send ntfy notification:", e));
            }
          }
          next[r.id] = r;
        }
        return { hostHealth: next };
      });
    } catch {
      /* transient - keep the previous readings rather than blanking the list */
    }
  },

  toggleFavoriteHost: (id) => set((state) => {
    const next = state.favoriteHostIds.includes(id)
      ? state.favoriteHostIds.filter((x) => x !== id)
      : [...state.favoriteHostIds, id];
    localStorage.setItem(FAVORITES_KEY, JSON.stringify(next));
    return { favoriteHostIds: next };
  }),

  restoreLastSession: async () => {
    const snap = stashedSnapshot;
    stashedSnapshot = null;
    if (!snap || !snap.tabs.length) return;

    const hosts = get().hosts;
    const panes = snap.panes.length ? snap.panes : ["default"];
    const startPane =
      snap.activePaneId && panes.includes(snap.activePaneId) ? snap.activePaneId : panes[0];
    // Lay down the pane structure first; tabs get connected into each pane below.
    set({
      panes,
      paneNames: snap.paneNames ?? {},
      activePaneId: startPane,
      activeTabIds: Object.fromEntries(panes.map((p) => [p, null])),
    });

    const desiredActive: Record<string, string> = {};
    for (const paneId of panes) {
      for (const t of snap.tabs.filter((x) => x.paneId === paneId)) {
        // connectToHost / openLocalShell attach the new tab to activePaneId.
        set({ activePaneId: paneId });
        try {
          if (t.kind === "local") {
            await get().openLocalShell();
          } else {
            const host = hosts.find((h) => h.id === t.hostId);
            if (!host) continue;
            await get().connectToHost(host);
          }
        } catch {
          continue; // host gone, auth failed, offline - skip and keep going
        }
        const addedId = get().activeTabIds[paneId];
        if (!addedId) continue;
        if (t.title) {
          set((state) => ({
            tabs: state.tabs.map((tb) => (tb.id === addedId ? { ...tb, title: t.title } : tb)),
          }));
        }
        if (t.active) desiredActive[paneId] = addedId;
      }
    }

    set((state) => ({
      activeTabIds: { ...state.activeTabIds, ...desiredActive },
      activePaneId: startPane,
    }));
  },

  setAutoReconnect: (on) => {
    localStorage.setItem("ssh-mgr:auto-reconnect", on ? "1" : "0");
    set({ autoReconnect: on });
  },

  setBroadcastInput: (on) => set({ broadcastInput: on }),

  reconnectTab: async (tabId) => {
    const tab = get().tabs.find((t) => t.id === tabId);
    if (!tab || tab.kind !== "ssh" || !tab.host) throw new Error("Not a reconnectable host");
    const newSessionId = await invoke<string>("ssh_connect", { host: withResolvedJump(tab.host, get().hosts) });
    // Retire the old session's output buffer so the fresh view starts clean.
    clearTerminalOutput(tab.sessionId);
    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: "connection",
        message: `Reconnected to ${tab.host.name}`,
        host_id: tab.host.id,
      },
    }).catch(console.error);
    set((state) => ({
      tabs: state.tabs.map((t) =>
        t.id === tabId ? { ...t, sessionId: newSessionId, connected: true } : t
      ),
    }));
  },

  importSshConfig: async () => {
    const parsed = await invoke<Host[]>("import_ssh_config");
    const existing = get().hosts;
    const seen = new Set(
      existing.map((h) => `${h.username}@${h.hostname}:${h.port}`.toLowerCase())
    );
    const fresh = parsed.filter(
      (h) => !seen.has(`${h.username}@${h.hostname}:${h.port}`.toLowerCase())
    );
    let added = 0;
    for (const host of fresh) {
      const saved = await invoke<Host>("save_host", { host });
      set((state) => ({ hosts: [...state.hosts, saved] }));
      added++;
    }
    if (added > 0) {
      invoke("log_history", {
        event: {
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          event_type: "host_imported",
          message: `Imported ${added} host${added === 1 ? "" : "s"} from ~/.ssh/config`,
        },
      }).catch(console.error);
      autoPush();
    }
    return added;
  },

  startForward: async (sessionId, forward, host) => {
    await invoke("start_forward", {
      sessionId,
      forwardId: forward.id,
      host,
      kind: forward.kind ?? "local",
      localPort: forward.local_port,
      remoteHost: forward.remote_host,
      remotePort: forward.remote_port,
      bindHost: forward.bind_host ?? null,
    });
    set((s) => ({
      activeForwards: new Set([...s.activeForwards, `${sessionId}:${forward.id}`]),
    }));
  },

  stopForward: async (sessionId, forwardId) => {
    await invoke("stop_forward", { sessionId, forwardId });
    set((s) => {
      const next = new Set(s.activeForwards);
      next.delete(`${sessionId}:${forwardId}`);
      return { activeForwards: next };
    });
  },

  checkVaultExists: () => invoke<boolean>("vault_exists"),

  unlock: async (password) => {
    const hosts = await invoke<Host[]>("unlock_vault", { password });
    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: "vault_unlocked",
        message: "Vault unlocked",
      }
    }).catch(console.error);
    let finalHosts = hosts;
    // Auto-sync: pull the latest from cloud right after unlocking (best-effort).
    if (isAutoSyncEnabled()) {
      try {
        const outcome = await invoke<PullOutcome>("sync_pull", { password });
        if (outcome.kind === "pulled") finalHosts = outcome.hosts;
      } catch {
        /* not configured / offline - ignore */
      }
    }
    const snippets = await invoke<Snippet[]>("get_snippets").catch(() => []);
    // If the user has never made a choice, turn the flag on when agent hosts already
    // exist, so their config isn't hidden behind a feature they never opted into.
    if (!relayFlagWasSet() && hasAgentHosts(finalHosts)) {
      localStorage.setItem(RELAY_FLAG_KEY, "1");
      set({ relayEnabled: true });
    }
    // Capture the saved layout now, before `unlocked` flips and the live
    // snapshotter overwrites it with the empty fresh state. App triggers the
    // actual restore once hosts are in place.
    stashedSnapshot = get().restoreSessionEnabled ? loadSessionSnapshot() : null;
    set({ unlocked: true, hosts: finalHosts, snippets });
  },

  lock: () => {
    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: "vault_locked",
        message: "Vault locked manually",
      }
    }).catch(console.error);
    invoke("lock_vault");
    get().tabs.forEach((t) =>
      invoke("ssh_disconnect", { sessionId: t.sessionId }).catch(() => {})
    );
    set({ unlocked: false, hosts: [], notes: [], snippets: [], tabs: [], panes: ["default"], activePaneId: "default", paneNames: {}, activeTabIds: { "default": null }, hostHealth: {} });
  },

  saveHost: async (host) => {
    const saved = await invoke<Host>("save_host", { host });
    
    const exists = get().hosts.find((h) => h.id === saved.id);
    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: exists ? "host_edited" : "host_added",
        message: exists ? `Host edited: ${saved.name}` : `Host added: ${saved.name}`,
        host_id: saved.id,
      }
    }).catch(console.error);

    set((state) => {
      const existsInState = state.hosts.find((h) => h.id === saved.id);
      return {
        hosts: existsInState
          ? state.hosts.map((h) => (h.id === saved.id ? saved : h))
          : [...state.hosts, saved],
      };
    });
    autoPush();
    return saved;
  },

  deleteHost: async (id) => {
    const host = get().hosts.find(h => h.id === id);
    if (host) {
      invoke("log_history", {
        event: {
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          event_type: "host_deleted",
          message: `Host deleted: ${host.name}`,
          host_id: id,
        }
      }).catch(console.error);
    }
    await invoke("delete_host", { id });
    set((state) => {
      const favoriteHostIds = state.favoriteHostIds.filter((x) => x !== id);
      if (favoriteHostIds.length !== state.favoriteHostIds.length) {
        localStorage.setItem(FAVORITES_KEY, JSON.stringify(favoriteHostIds));
      }
      return { hosts: state.hosts.filter((h) => h.id !== id), favoriteHostIds };
    });
    autoPush();
  },

  connectToHost: async (host) => {
    const sessionId = await invoke<string>("ssh_connect", { host: withResolvedJump(host, get().hosts) });
    const tabId = crypto.randomUUID();
    
    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: "connection",
        message: `Connected to ${host.name}`,
        host_id: host.id,
      }
    }).catch(console.error);

    set((state) => ({
      tabs: [...state.tabs, { id: tabId, sessionId, kind: "ssh", host, connected: true, paneId: state.activePaneId }],
      activeTabIds: { ...state.activeTabIds, [state.activePaneId]: tabId },
    }));
    return sessionId;
  },

  updaterKeyId: () => invoke<string | null>("updater_key_id"),
  checkMcpBinary: () => invoke<McpBinaryCheck>("check_mcp_binary"),
  checkForUpdate: async () => {
    try {
      const info = await invoke<UpdateInfo>("check_for_update");
      set({ updateInfo: info });
    } catch {
      // Offline or rate-limited - fail silently, leave updateInfo as-is.
    }
  },

  openLocalShell: async () => {
    const sessionId = await invoke<string>("local_connect");
    const tabId = crypto.randomUUID();

    set((state) => ({
      tabs: [...state.tabs, { id: tabId, sessionId, kind: "local", connected: true, paneId: state.activePaneId }],
      activeTabIds: { ...state.activeTabIds, [state.activePaneId]: tabId },
    }));
  },

  dockerShell: async (sessionId, local, containerId, containerName) => {
    // Backend opens an interactive `docker exec` PTY and returns a new session
    // id; we attach a terminal tab to it (ssh-style for remote, local for local).
    const newSessionId = await invoke<string>("docker_shell", { sessionId, local, containerId });
    const tabId = crypto.randomUUID();
    const parent = get().tabs.find((t) => t.sessionId === sessionId);
    set((state) => ({
      tabs: [
        ...state.tabs,
        {
          id: tabId,
          sessionId: newSessionId,
          kind: local ? "local" : "ssh",
          host: parent?.host,
          title: `🐳 ${containerName || containerId}`,
          connected: true,
          paneId: state.activePaneId,
        },
      ],
      activeTabIds: { ...state.activeTabIds, [state.activePaneId]: tabId },
    }));
  },

  closeTab: (tabId) => {
    const tab = get().tabs.find((t) => t.id === tabId);
    if (tab) {
      clearTerminalOutput(tab.sessionId);
      if (tab.kind === "local") {
        invoke("local_disconnect", { sessionId: tab.sessionId }).catch(() => {});
      } else {
        invoke("ssh_disconnect", { sessionId: tab.sessionId }).catch(() => {});
        if (tab.connected && tab.host) {
          invoke("log_history", {
            event: {
              id: crypto.randomUUID(),
              timestamp: Date.now(),
              event_type: "connection",
              message: `Disconnected from ${tab.host.name}`,
              host_id: tab.host.id,
            }
          }).catch(console.error);
        }
      }
    }
    set((state) => {
      const newTabs = state.tabs.filter((t) => t.id !== tabId);
      const paneId = tab!.paneId;
      const paneTabs = newTabs.filter(t => t.paneId === paneId);
      const newActiveForPane =
        state.activeTabIds[paneId] === tabId
          ? paneTabs.length > 0 ? paneTabs[paneTabs.length - 1].id : null
          : state.activeTabIds[paneId];
      // Remove all active forwards for this session
      const sid = tab?.sessionId;
      const newForwards = sid
        ? new Set([...state.activeForwards].filter((k) => !k.startsWith(`${sid}:`)))
        : state.activeForwards;
      return { tabs: newTabs, activeTabIds: { ...state.activeTabIds, [paneId]: newActiveForPane }, activeForwards: newForwards };
    });
  },

  setActiveTab: (tabId) => set((state) => {
    const paneId = state.tabs.find((t) => t.id === tabId)?.paneId;
    if (!paneId) return state;
    return { activeTabIds: { ...state.activeTabIds, [paneId]: tabId }, activePaneId: paneId };
  }),

  splitPane: (paneId) => set((state) => {
    const newPaneId = crypto.randomUUID();
    const paneIndex = state.panes.indexOf(paneId);
    if (paneIndex === -1) return state;
    const newPanes = [...state.panes];
    newPanes.splice(paneIndex + 1, 0, newPaneId);
    return {
      panes: newPanes,
      activePaneId: newPaneId,
      activeTabIds: { ...state.activeTabIds, [newPaneId]: null },
    };
  }),

  closePane: (paneId) => {
    // Before updating state, cleanly disconnect all tabs in this pane
    const tabsInPane = get().tabs.filter((t) => t.paneId === paneId);
    tabsInPane.forEach((tab) => {
      clearTerminalOutput(tab.sessionId);
      if (tab.kind === "local") {
        invoke("local_disconnect", { sessionId: tab.sessionId }).catch(() => {});
      } else {
        invoke("ssh_disconnect", { sessionId: tab.sessionId }).catch(() => {});
      }
    });

    set((state) => {
      const newPanes = state.panes.filter((p) => p !== paneId);
      if (newPanes.length === 0) return state; // Don't close the last pane
      const newTabs = state.tabs.filter((t) => t.paneId !== paneId);
      const newActiveTabIds = { ...state.activeTabIds };
      delete newActiveTabIds[paneId];
      const newPaneNames = { ...state.paneNames };
      delete newPaneNames[paneId];

      const newActivePaneId = state.activePaneId === paneId ? newPanes[newPanes.length - 1] : state.activePaneId;

      return {
        panes: newPanes,
        tabs: newTabs,
        activeTabIds: newActiveTabIds,
        paneNames: newPaneNames,
        activePaneId: newActivePaneId,
      };
    });
  },

  setActivePane: (paneId) => set({ activePaneId: paneId }),

  renamePane: (paneId, name) => set((state) => {
    const trimmed = name.trim();
    const paneNames = { ...state.paneNames };
    // Blank clears the custom name so the pane reverts to its default "Pane N".
    if (trimmed) paneNames[paneId] = trimmed;
    else delete paneNames[paneId];
    return { paneNames };
  }),

  moveTabToPane: (tabId, targetPaneId) => set((state) => {
    const tab = state.tabs.find((t) => t.id === tabId);
    if (!tab || tab.paneId === targetPaneId || !state.panes.includes(targetPaneId)) return state;
    const sourcePaneId = tab.paneId;
    const newTabs = state.tabs.map((t) => (t.id === tabId ? { ...t, paneId: targetPaneId } : t));
    // If the moved tab was active in its old pane, promote another tab there.
    const sourceTabs = newTabs.filter((t) => t.paneId === sourcePaneId);
    const sourceActive =
      state.activeTabIds[sourcePaneId] === tabId
        ? sourceTabs.length > 0 ? sourceTabs[sourceTabs.length - 1].id : null
        : state.activeTabIds[sourcePaneId];
    return {
      tabs: newTabs,
      activePaneId: targetPaneId,
      activeTabIds: { ...state.activeTabIds, [sourcePaneId]: sourceActive, [targetPaneId]: tabId },
    };
  }),

  moveTabToNewSplit: (tabId) => set((state) => {
    const tab = state.tabs.find((t) => t.id === tabId);
    if (!tab) return state;
    const sourcePaneId = tab.paneId;
    const newPaneId = crypto.randomUUID();
    const idx = state.panes.indexOf(sourcePaneId);
    const newPanes = [...state.panes];
    newPanes.splice(idx + 1, 0, newPaneId);
    const newTabs = state.tabs.map((t) => (t.id === tabId ? { ...t, paneId: newPaneId } : t));
    const sourceTabs = newTabs.filter((t) => t.paneId === sourcePaneId);
    const sourceActive =
      state.activeTabIds[sourcePaneId] === tabId
        ? sourceTabs.length > 0 ? sourceTabs[sourceTabs.length - 1].id : null
        : state.activeTabIds[sourcePaneId];
    return {
      panes: newPanes,
      tabs: newTabs,
      activePaneId: newPaneId,
      activeTabIds: { ...state.activeTabIds, [sourcePaneId]: sourceActive, [newPaneId]: tabId },
    };
  }),

  markTabDisconnected: (sessionId) => {
    const tab = get().tabs.find((t) => t.sessionId === sessionId);
    if (tab && tab.connected && tab.host) {
      invoke("log_history", {
        event: {
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          event_type: "connection",
          message: `Disconnected from ${tab.host.name}`,
          host_id: tab.host.id,
        }
      }).catch(console.error);
    }
    set((state) => ({
      tabs: state.tabs.map((t) =>
        t.sessionId === sessionId ? { ...t, connected: false } : t
      ),
    }));
  },

  generateSshKey: async () => {
    const key = await invoke<SshKeyPair>("generate_ssh_key");
    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: "key_generated",
        message: "Generated new SSH Key Pair",
      }
    }).catch(console.error);
    return key;
  },

  loadKeyFile: (path: string) => invoke<string>("read_key_file", { path }),

  exportHost: async (host: Host, path: string) => {
    await invoke("export_host", { host, path });
    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: "host_exported",
        message: `Exported host: ${host.name}`,
        host_id: host.id,
      }
    }).catch(console.error);
  },

  exportHostEncrypted: async (host: Host, path: string, password: string) => {
    await invoke("export_host_encrypted", { host, path, password });
    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: "host_exported",
        message: `Exported host (encrypted): ${host.name}`,
        host_id: host.id,
      }
    }).catch(console.error);
  },

  exportSshKey: async (content: string, path: string) => {
    await invoke("export_ssh_key", { content, path });
    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: "key_exported",
        message: `Exported SSH Key to file`,
      }
    }).catch(console.error);
  },

  importHostFromFile: async (path: string) => {
    const host = await invoke<Host>("import_host", { path });
    const saved = await invoke<Host>("save_host", { host });
    
    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: "host_imported",
        message: `Imported host from file: ${saved.name}`,
        host_id: saved.id,
      }
    }).catch(console.error);

    set((state) => ({ hosts: [...state.hosts, saved] }));
    autoPush();
    return saved;
  },

  profileIsEncrypted: (path: string) => invoke<boolean>("profile_is_encrypted", { path }),

  importHostEncrypted: async (path: string, password: string) => {
    const host = await invoke<Host>("import_host_encrypted", { path, password });
    const saved = await invoke<Host>("save_host", { host });

    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: "host_imported",
        message: `Imported encrypted host from file: ${saved.name}`,
        host_id: saved.id,
      }
    }).catch(console.error);

    set((state) => ({ hosts: [...state.hosts, saved] }));
    autoPush();
    return saved;
  },

  exportSshConfig: async () => {
    const count = await invoke<number>("export_ssh_config");
    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: "host_exported",
        message: `Exported ${count} host${count === 1 ? "" : "s"} to ~/.ssh/config`,
      },
    }).catch(console.error);
    return count;
  },

  installPublicKey: async (host, publicKey) => {
    await invoke("install_public_key", { host, publicKey });
    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: "key_installed",
        message: `Installed public key on ${host.name}`,
        host_id: host.id || null,
      },
    }).catch(console.error);
  },

  processesList: (sessionId, local) =>
    invoke<ProcessInfo[]>("processes_list", { sessionId, local }),
  processKill: (sessionId, local, pid, signal) =>
    invoke<void>("process_kill", { sessionId, local, pid, signal }),

  cronList: (sessionId, local) => invoke<CronTable>("cron_list", { sessionId, local }),
  cronSave: (sessionId, local, lines, token) =>
    invoke<CronTable>("cron_save", { sessionId, local, lines, token }),
  cronPreview: (schedule, hostNow, hostOffsetMin) =>
    invoke<CronPreview>("cron_preview", { schedule, hostNow, hostOffsetMin }),

  checkCommandDanger: (line) => invoke<DangerMatch | null>("check_command_danger", { line }),
  auditKeys: () => invoke<AuditReport>("audit_keys"),
  sweepKeys: (extraDirs) => invoke<SweepReport>("sweep_keys", { extraDirs }),
  importKeyFromDisk: (path, hostId, name) =>
    invoke<ImportOutcome>("import_key_from_disk", { path, hostId, name }),
  evictKeyFromDisk: (path, overrideConfig) =>
    invoke<string>("evict_key_from_disk", { path, overrideConfig }),
  exportKeyToDisk: (hostId, path, includePublic) =>
    invoke<string>("export_key_to_disk", { hostId, path, includePublic }),
  probeHostAlgorithms: (hosts) => invoke<HostProbe[]>("probe_host_algorithms", { hosts }),
  writeTextFile: (content, path) => invoke<void>("write_text_file", { content, path }),
  rotateKey: async (hostId) => {
    const outcome = await invoke<RotateOutcome>("rotate_key", { hostId });
    // Rotation rewrites the host in the vault, so the copy in the store - the
    // one the host form and every connect path reads - is now the old key.
    set({ hosts: await invoke<Host[]>("get_hosts") });
    return outcome;
  },

  aiGetConfig: () => invoke<AiConfigView | null>("ai_get_config"),
  cloudGetConfig: () => invoke<CloudConfigView | null>("cloud_get_config"),
  cloudSetConfig: (config) => invoke<CloudConfigView>("cloud_set_config", { config }),
  cloudListMachines: () => invoke<CloudMachine[]>("cloud_list_machines"),
  cloudAddMachine: (name) => invoke<CloudAddedMachine>("cloud_add_machine", { name }),
  cloudRemoveMachine: (agentId) => invoke<void>("cloud_remove_machine", { agentId }),
  aiSetConfig: (config) => invoke<AiConfigView>("ai_set_config", { config }),
  aiListModels: () => invoke<AiModelInfo[]>("ai_list_models"),
  aiSend: (requestId, system, messages, allowSecrets) =>
    invoke<RedactionHit[]>("ai_send", { requestId, system, messages, allowSecrets }),
  aiPreview: (system, messages, allowSecrets) =>
    invoke<AiPreview>("ai_preview", { system, messages, allowSecrets }),
  aiCancel: (requestId) => invoke<void>("ai_cancel", { requestId }),

  getHistory: () => invoke<HistoryEvent[]>("get_history"),
  fetchShellHistory: async (sessionId, hostId) => {
    const merged = await invoke<string[]>("fetch_shell_history", { sessionId, hostId });
    autoPush();
    return merged;
  },
  getShellHistory: (hostId) => invoke<string[]>("get_shell_history", { hostId }),
  clearShellHistory: async (hostId) => {
    await invoke("clear_shell_history", { hostId });
    autoPush();
  },

  refreshNotes: async () => {
    set({ notes: await invoke<Note[]>("get_notes") });
  },

  saveNote: async (note) => {
    const saved = await invoke<Note>("save_note", { note });
    set((state) => ({
      notes: state.notes.some((n) => n.id === saved.id)
        ? state.notes.map((n) => (n.id === saved.id ? saved : n))
        : [...state.notes, saved],
    }));
    autoPush();
    return saved;
  },

  deleteNote: async (id) => {
    await invoke("delete_note", { id });
    set((state) => ({ notes: state.notes.filter((n) => n.id !== id) }));
    autoPush();
  },

  refreshSnippets: async () => {
    const snippets = await invoke<Snippet[]>("get_snippets");
    set({ snippets });
  },

  saveSnippet: async (snippet) => {
    const saved = await invoke<Snippet>("save_snippet", { snippet });
    set((state) => {
      const exists = state.snippets.find((s) => s.id === saved.id);
      return {
        snippets: exists
          ? state.snippets.map((s) => (s.id === saved.id ? saved : s))
          : [...state.snippets, saved],
      };
    });
    autoPush();
    return saved;
  },

  deleteSnippet: async (id) => {
    await invoke("delete_snippet", { id });
    set((state) => ({
      snippets: state.snippets.filter((s) => s.id !== id),
      // Drop the deleted snippet from any host's on-connect selection (backend
      // already persisted this; keep local state in sync).
      hosts: state.hosts.map((h) => ({
        ...h,
        on_connect_snippets: (h.on_connect_snippets ?? []).filter((sid) => sid !== id),
      })),
    }));
    autoPush();
  },

  syncGetConfig: () => invoke<SyncConfigView | null>("sync_get_config"),

  syncSetConfig: (config) => invoke<SyncConfigView>("sync_set_config", { config }),

  syncTest: () => invoke<boolean>("sync_test"),

  syncPush: async (force = false) => {
    const outcome = await invoke<PushOutcome>("sync_push", { force });
    if (outcome.kind === "pushed") {
      invoke("log_history", {
        event: {
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          event_type: "vault_synced",
          message: "Vault pushed to cloud",
        },
      }).catch(console.error);
    }
    return outcome;
  },

  syncPull: async (password) => {
    const outcome = await invoke<PullOutcome>("sync_pull", { password });
    if (outcome.kind === "pulled") {
      const snippets = await invoke<Snippet[]>("get_snippets").catch(() => []);
      set({ hosts: outcome.hosts, snippets });
      invoke("log_history", {
        event: {
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          event_type: "vault_synced",
          message: "Vault pulled from cloud",
        },
      }).catch(console.error);
    }
    return outcome;
  },

  syncRestore: async (config, password) => {
    const hosts = await invoke<Host[]>("sync_restore", { config, password });
    invoke("log_history", {
      event: {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        event_type: "vault_synced",
        message: "Vault restored from cloud",
      },
    }).catch(console.error);
    const snippets = await invoke<Snippet[]>("get_snippets").catch(() => []);
    if (!relayFlagWasSet() && hasAgentHosts(hosts)) {
      localStorage.setItem(RELAY_FLAG_KEY, "1");
      set({ relayEnabled: true });
    }
    set({ unlocked: true, hosts, snippets });
    return hosts;
  },

  sftpOpen: (sessionId, host) => invoke<string>("sftp_open", { sessionId, host }),
  sftpList: (sessionId, path) => invoke<SftpEntry[]>("sftp_list", { sessionId, path }),
  sftpDownload: (sessionId, remote, local) =>
    invoke<void>("sftp_download", { sessionId, remote, local }),
  sftpUpload: (sessionId, local, remote) =>
    invoke<void>("sftp_upload", { sessionId, local, remote }),
  sftpReadFile: (sessionId, path) =>
    invoke<string>("sftp_read_file", { sessionId, path }),
  sftpWriteFile: (sessionId, path, content) =>
    invoke<void>("sftp_write_file", { sessionId, path, content }),
  sftpRename: (sessionId, from, to) => invoke<void>("sftp_rename", { sessionId, from, to }),
  sftpDelete: (sessionId, path, isDir) =>
    invoke<void>("sftp_delete", { sessionId, path, isDir }),
  sftpMkdir: (sessionId, path) => invoke<void>("sftp_mkdir", { sessionId, path }),
  sftpChmod: (sessionId, path, mode) => invoke<void>("sftp_chmod", { sessionId, path, mode }),
  sftpClose: (sessionId) => invoke<void>("sftp_close", { sessionId }),
  dockerPs: (sessionId, local, all) => invoke<DockerContainer[]>("docker_ps", { sessionId, local, all }),
  dockerAction: (sessionId, local, containerId, action) =>
    invoke<void>("docker_action", { sessionId, local, containerId, action }),
  dockerLogs: (sessionId, local, containerId, tail) =>
    invoke<string>("docker_logs", { sessionId, local, containerId, tail }),
  metricsStart: (sessionId, local) => invoke<string>("metrics_start", { sessionId, local }),
  metricsStop: (streamId) => invoke<void>("metrics_stop", { streamId }),
  dockerImages: (sessionId, local) => invoke<DockerImage[]>("docker_images", { sessionId, local }),
  dockerVolumes: (sessionId, local) => invoke<DockerVolume[]>("docker_volumes", { sessionId, local }),
  dockerNetworks: (sessionId, local) => invoke<DockerNetwork[]>("docker_networks", { sessionId, local }),
  dockerLogsStream: (sessionId, local, containerId, tail) =>
    invoke<string>("docker_logs_stream", { sessionId, local, containerId, tail }),
  dockerLogsStreamStop: (streamId) => invoke<void>("docker_logs_stream_stop", { streamId }),

  changeMasterPassword: (currentPassword, newPassword) =>
    invoke<void>("change_master_password", { currentPassword, newPassword }),

  verifyHostKey: (host) => invoke<HostKeyVerdict>("verify_host_key", { host }),
  trustHostKey: (host, fingerprint) => invoke<void>("trust_host_key", { host, fingerprint }),
  forgetHostKey: (host) => invoke<void>("forget_host_key", { host }),

  startRecording: async (sessionId, filename) => {
    await invoke("start_recording", { sessionId, filename });
  },
  stopRecording: async (sessionId) => {
    await invoke("stop_recording", { sessionId });
  },
  listRecordings: async () => {
    return await invoke("list_recordings");
  },
  readRecording: async (filename) => {
    return await invoke("read_recording", { filename });
  },
  deleteRecording: async (filename) => {
    await invoke("delete_recording", { filename });
  },
  setRecordingState: (sessionId, isRecording) => {
    set((state) => {
      const next = new Set(state.recordingSessions);
      if (isRecording) next.add(sessionId);
      else next.delete(sessionId);
      return { recordingSessions: next };
    });
  },

  mcpSetHostPolicy: (hostId, mode, rulesText) =>
    invoke<void>("mcp_set_host_policy", { hostId, mode, rulesText }),
  mcpSetGlobalRules: (rulesText) =>
    invoke<void>("mcp_set_global_rules", { rulesText }),
  mcpGetConfig: async () => {
    return await invoke<McpConfig>("mcp_get_config");
  },
  mcpSetPassword: async (password: string) => {
    await invoke("mcp_set_password", { password });
  },
  mcpSetExposedHosts: async (hostIds: string[]) => {
    await invoke("mcp_set_exposed_hosts", { hostIds });
  },
}));

// Live session snapshotter: while unlocked with restore enabled, persist the
// tab/pane layout (debounced) so a lock, quit, or crash can rebuild it. Guarded
// on `unlocked` so the lock reset (which empties tabs) never clobbers the saved
// layout - the last good snapshot stays on disk until the next real change.
let snapshotTimer: ReturnType<typeof setTimeout> | undefined;
useVaultStore.subscribe((state) => {
  if (!state.unlocked || !state.restoreSessionEnabled) return;
  clearTimeout(snapshotTimer);
  snapshotTimer = setTimeout(() => {
    try {
      localStorage.setItem(SESSION_KEY, JSON.stringify(serializeSession(useVaultStore.getState())));
    } catch {
      /* storage full / unavailable - restore is best-effort */
    }
  }, 400);
});
