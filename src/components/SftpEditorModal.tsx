import { useState } from "react";
import Editor, { Monaco } from "@monaco-editor/react";
import { useVaultStore } from "../store";
import { THEMES } from "../themes";

interface Props {
  sessionId: string;
  path: string;
  initialContent: string;
  onClose: () => void;
  onSaved: () => void;
}

// Map file extensions to Monaco language identifiers
function getLanguage(path: string): string {
  const name = path.split(/[/\\]/).pop() || "";
  const ext = name.split(".").pop()?.toLowerCase();
  
  if (name === "Dockerfile") return "dockerfile";
  if (name.startsWith(".bash") || name.startsWith(".zsh") || ext === "sh") return "shell";
  
  switch (ext) {
    case "js": return "javascript";
    case "ts": return "typescript";
    case "jsx": return "javascript";
    case "tsx": return "typescript";
    case "json": return "json";
    case "html": return "html";
    case "css": return "css";
    case "scss": return "scss";
    case "md": return "markdown";
    case "py": return "python";
    case "rb": return "ruby";
    case "rs": return "rust";
    case "go": return "go";
    case "java": return "java";
    case "c": return "c";
    case "cpp": return "cpp";
    case "yaml": 
    case "yml": return "yaml";
    case "xml": return "xml";
    case "ini":
    case "conf":
    case "toml": return "ini";
    case "sql": return "sql";
    default: return "plaintext";
  }
}

export function SftpEditorModal({ sessionId, path, initialContent, onClose, onSaved }: Props) {
  const { sftpWriteFile, theme } = useVaultStore();
  const [content, setContent] = useState(initialContent);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  
  const currentThemeDef = THEMES.find(t => t.id === theme) || THEMES[0];
  const monacoThemeName = `custom-${currentThemeDef.id}`;
  const language = getLanguage(path);

  const handleEditorWillMount = (monaco: Monaco) => {
    monaco.editor.defineTheme(monacoThemeName, {
      base: currentThemeDef.dark ? 'vs-dark' : 'vs',
      inherit: true,
      rules: [],
      colors: {
        'editor.background': currentThemeDef.ui.bg,
        'editor.foreground': currentThemeDef.ui.text,
        'editorCursor.foreground': currentThemeDef.term.cursor,
        'editor.lineHighlightBackground': currentThemeDef.ui.overlay,
        'editorLineNumber.foreground': currentThemeDef.ui.subtle,
        'editor.selectionBackground': currentThemeDef.ui.muted,
        'editor.inactiveSelectionBackground': currentThemeDef.ui.surface,
      }
    });
  };

  const handleSave = async () => {
    setSaving(true);
    setError("");
    try {
      await sftpWriteFile(sessionId, path, content);
      onSaved();
    } catch (e: any) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-overlay" style={{ zIndex: 9999 }}>
      <div 
        className="modal" 
        style={{ 
          width: "90vw", 
          height: "85vh", 
          maxWidth: "1200px", 
          display: "flex", 
          flexDirection: "column" 
        }}
      >
        <div className="modal-header">
          <h2>Editing: {path}</h2>
          <button className="icon-btn" onClick={onClose} disabled={saving}>✕</button>
        </div>

        {error && <div className="form-error" style={{ margin: "10px 20px" }}>{error}</div>}

        <div style={{ flex: 1, minHeight: 0, padding: "10px", background: "var(--bg-card)" }}>
          <Editor
            height="100%"
            language={language}
            theme={monacoThemeName}
            beforeMount={handleEditorWillMount}
            value={content}
            onChange={(value) => setContent(value || "")}
            options={{
              minimap: { enabled: false },
              fontSize: 13,
              fontFamily: "var(--font-mono)",
              scrollBeyondLastLine: false,
              wordWrap: "on",
              automaticLayout: true
            }}
          />
        </div>

        <div className="modal-footer" style={{ borderTop: "1px solid var(--border)", padding: "12px 20px" }}>
          <button 
            className="btn btn-primary" 
            onClick={handleSave} 
            disabled={saving || content === initialContent}
          >
            {saving ? "Saving…" : "Save"}
          </button>
          <button className="btn btn-subtle" onClick={onClose} disabled={saving}>Cancel</button>
        </div>
      </div>
    </div>
  );
}
