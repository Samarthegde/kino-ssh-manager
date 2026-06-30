import { invoke } from "@tauri-apps/api/core";
import { create } from "zustand";

export type DefaultAuth = "Password" | "SshKey";

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
  activeTabIds: Record<string, string | null>;
  theme: string;
  idleLockMinutes: number;
  activeForwards: Set<string>;

  checkVaultExists: () => Promise<boolean>;
  setTheme: (id: string) => void;
  setIdleLockMinutes: (minutes: number) => void;
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
  markTabDisconnected: (sessionId: string) => void;
  generateSshKey: () => Promise<SshKeyPair>;
  loadKeyFile: (path: string) => Promise<string>;
  exportHost: (host: Host, path: string) => Promise<void>;
  exportSshKey: (content: string, path: string) => Promise<void>;
  importHostFromFile: (path: string) => Promise<Host>;
  getHistory: () => Promise<HistoryEvent[]>;
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
}

const AUTO_SYNC_KEY = "ssh-mgr:autosync";
export function isAutoSyncEnabled() {
  return localStorage.getItem(AUTO_SYNC_KEY) === "1";
}
export function setAutoSyncEnabled(on: boolean) {
  localStorage.setItem(AUTO_SYNC_KEY, on ? "1" : "0");
}
// Best-effort push after a vault change; silent on failure/conflict.
function autoPush() {
  if (isAutoSyncEnabled()) invoke("sync_push", { force: false }).catch(() => {});
}

export const useVaultStore = create<VaultStore>((set, get) => ({
  unlocked: false,
  hosts: [],
  snippets: [],
  tabs: [],
  panes: ["default"],
  activePaneId: "default",
  activeTabIds: { "default": null },
  theme: localStorage.getItem("ssh-mgr:theme") ?? "catppuccin-mocha",
  idleLockMinutes: Number(localStorage.getItem("ssh-mgr:idle-lock") ?? "0"),
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
        /* not configured / offline — ignore */
      }
    }
    const snippets = await invoke<Snippet[]>("get_snippets").catch(() => []);
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
    set({ unlocked: false, hosts: [], tabs: [], panes: ["default"], activePaneId: "default", activeTabIds: { "default": null } });
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
    set((state) => ({ hosts: state.hosts.filter((h) => h.id !== id) }));
    autoPush();
  },

  connectToHost: async (host) => {
    const sessionId = await invoke<string>("ssh_connect", { host });
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

  checkForUpdate: async () => {
    try {
      const info = await invoke<UpdateInfo>("check_for_update");
      set({ updateInfo: info });
    } catch {
      // Offline or rate-limited — fail silently, leave updateInfo as-is.
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
      
      const newActivePaneId = state.activePaneId === paneId ? newPanes[newPanes.length - 1] : state.activePaneId;
      
      return {
        panes: newPanes,
        tabs: newTabs,
        activeTabIds: newActiveTabIds,
        activePaneId: newActivePaneId,
      };
    });
  },

  setActivePane: (paneId) => set({ activePaneId: paneId }),

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

  getHistory: () => invoke<HistoryEvent[]>("get_history"),

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
}));
