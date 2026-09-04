//! AI copilot - bring-your-own-key, powered by OpenRouter.
//!
//! One provider: **OpenRouter** (<https://openrouter.ai>), an OpenAI-compatible
//! gateway that fronts models from every major lab behind a single key and a
//! single endpoint. Auth is an API key on `Authorization: Bearer`. The key is
//! stored encrypted with the vault key in `ai.enc` - the same at-rest treatment
//! as the cloud-sync token.
//!
//! Responses stream: the SSE body is parsed on a blocking task and relayed as
//! `ai-delta-<id>` / `ai-thinking-<id>` / `ai-done-<id>` / `ai-error-<id>`
//! events, mirroring how docker log streams and metrics already work.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};

use crate::vault::{load_encrypted, save_encrypted, vault_path};

const OPENROUTER_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
const OPENROUTER_MODELS_URL: &str = "https://openrouter.ai/api/v1/models";
/// Sent on every request so kino shows up in OpenRouter's activity dashboard.
const APP_TITLE: &str = "kino";

pub const PROVIDER_OPENROUTER: &str = "openrouter";

/// A starting point only - model IDs move, so the UI can refresh the real list
/// from OpenRouter rather than trusting anything hardcoded here. `openrouter/auto`
/// is always valid: it routes each request to a capable model automatically.
const DEFAULT_MODEL: &str = "openrouter/auto";
const DEFAULT_EFFORT: &str = "medium";
/// We stream, so a generous cap costs nothing and avoids truncating a long
/// answer mid-script.
const MAX_TOKENS: u32 = 64000;

/// In-flight request id - cancel flag.
pub type AiCancels = Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>;

pub fn default_model() -> String {
    DEFAULT_MODEL.to_string()
}

fn default_provider() -> String {
    PROVIDER_OPENROUTER.to_string()
}
fn default_effort() -> String {
    DEFAULT_EFFORT.to_string()
}

/// Whether an effort value is one OpenRouter's `reasoning.effort` accepts;
/// anything else means "don't ask for reasoning at all".
fn is_reasoning_effort(effort: &str) -> bool {
    matches!(effort, "low" | "medium" | "high")
}

/// Persisted AI settings. Encrypted with the vault key in `ai.enc`.
#[derive(Serialize, Deserialize, Clone)]
pub struct AiConfig {
    /// Always "openrouter" today; kept so older/newer configs round-trip cleanly.
    #[serde(default = "default_provider")]
    pub provider: String,
    /// provider id - API key. A map (rather than a bare string) so the on-disk
    /// shape survives if more providers are ever added back.
    #[serde(default)]
    pub api_keys: HashMap<String, String>,
    /// provider id - selected model.
    #[serde(default)]
    pub models: HashMap<String, String>,
    /// low | medium | high - passed through as OpenRouter's reasoning effort.
    #[serde(default = "default_effort")]
    pub effort: String,
}

impl AiConfig {
    pub fn model(&self) -> String {
        self.models
            .get(&self.provider)
            .filter(|m| !m.is_empty())
            .cloned()
            .unwrap_or_else(default_model)
    }

    fn key(&self) -> String {
        self.api_keys
            .get(&self.provider)
            .cloned()
            .unwrap_or_default()
    }

    pub fn view(&self) -> AiConfigView {
        let has_api_key = !self.key().is_empty();
        AiConfigView {
            configured: has_api_key,
            provider: self.provider.clone(),
            model: self.model(),
            effort: self.effort.clone(),
            has_api_key,
        }
    }
}

/// What the frontend may see - never includes a key.
#[derive(Serialize)]
pub struct AiConfigView {
    pub configured: bool,
    pub provider: String,
    pub model: String,
    pub effort: String,
    pub has_api_key: bool,
}

/// What the frontend sends. An empty `api_key` means "keep the stored one".
#[derive(Deserialize)]
pub struct AiConfigInput {
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default)]
    pub api_key: String,
    pub model: Option<String>,
    pub effort: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AiMessage {
    /// "user" or "assistant"
    pub role: String,
    pub content: String,
}

#[derive(Serialize)]
pub struct AiModel {
    pub id: String,
    pub label: String,
}

fn config_path() -> std::path::PathBuf {
    vault_path().parent().unwrap().join("ai.enc")
}

pub fn load_config(key: &[u8; 32]) -> Option<AiConfig> {
    let path = config_path();
    if !path.exists() {
        return None;
    }
    load_encrypted::<AiConfig>(&path, key).ok()
}

pub fn save_config(config: &AiConfig, key: &[u8; 32], salt: &[u8; 16]) -> Result<(), String> {
    save_encrypted(&config_path(), config, key, salt)
}

#[tauri::command]
pub fn ai_get_config(
    state: tauri::State<'_, crate::AppState>,
) -> Result<Option<AiConfigView>, String> {
    let key = state.vault_key.lock().unwrap().ok_or("Vault is locked")?;
    Ok(load_config(&key).map(|c| c.view()))
}

#[tauri::command]
pub fn ai_set_config(
    state: tauri::State<'_, crate::AppState>,
    config: AiConfigInput,
) -> Result<AiConfigView, String> {
    let key = state.vault_key.lock().unwrap().ok_or("Vault is locked")?;
    let salt = state.vault_salt.lock().unwrap().ok_or("Vault is locked")?;

    let existing = load_config(&key);
    let mut api_keys = existing
        .as_ref()
        .map(|c| c.api_keys.clone())
        .unwrap_or_default();
    // An empty key means "unchanged", so the UI never echoes the secret back.
    if !config.api_key.is_empty() {
        api_keys.insert(config.provider.clone(), config.api_key);
    }
    let mut models = existing
        .as_ref()
        .map(|c| c.models.clone())
        .unwrap_or_default();
    if let Some(m) = config.model.filter(|m| !m.is_empty()) {
        models.insert(config.provider.clone(), m);
    }

    let next = AiConfig {
        provider: config.provider,
        api_keys,
        models,
        effort: config
            .effort
            .filter(|e| !e.is_empty())
            .or_else(|| existing.as_ref().map(|c| c.effort.clone()))
            .unwrap_or_else(default_effort),
    };
    save_config(&next, &key, &salt)?;
    Ok(next.view())
}

/// Resolved per-request credential: headers to set on the outgoing call.
struct Auth {
    headers: Vec<(String, String)>,
}

fn resolve_auth(config: &AiConfig) -> Result<Auth, String> {
    let key = config.key();
    if key.is_empty() {
        return Err("No OpenRouter API key stored - add one under Settings - AI Copilot.".into());
    }
    Ok(Auth {
        headers: vec![
            ("authorization".into(), format!("Bearer {key}")),
            // OpenRouter attribution headers - purely for its dashboard.
            ("x-title".into(), APP_TITLE.into()),
        ],
    })
}

/// Build the OpenRouter (OpenAI-compatible) request body. The system prompt is
/// prepended as a `system` message; reasoning is requested via OpenRouter's
/// unified `reasoning` field, which models that don't support it simply ignore.
fn build_body(config: &AiConfig, system: &str, messages: &[AiMessage]) -> serde_json::Value {
    let mut chat = Vec::with_capacity(messages.len() + 1);
    if !system.is_empty() {
        chat.push(serde_json::json!({ "role": "system", "content": system }));
    }
    for m in messages {
        chat.push(serde_json::json!({ "role": m.role, "content": m.content }));
    }

    let mut body = serde_json::json!({
        "model": config.model(),
        "max_tokens": MAX_TOKENS,
        "stream": true,
        "messages": chat,
    });
    if is_reasoning_effort(&config.effort) {
        body["reasoning"] = serde_json::json!({ "effort": config.effort });
    }
    body
}

/// What one SSE payload meant.
#[derive(Debug, PartialEq)]
enum Chunk {
    Text(String),
    Thinking(String),
    Err(String),
    Ignore,
}

fn parse_chunk(v: &serde_json::Value) -> Chunk {
    if let Some(msg) = v["error"]["message"].as_str() {
        return Chunk::Err(msg.to_string());
    }
    let delta = &v["choices"][0]["delta"];
    // OpenRouter surfaces reasoning as `reasoning` (some providers: `reasoning_content`).
    if let Some(t) = delta["reasoning"]
        .as_str()
        .or_else(|| delta["reasoning_content"].as_str())
        .filter(|t| !t.is_empty())
    {
        return Chunk::Thinking(t.to_string());
    }
    if let Some(t) = delta["content"].as_str().filter(|t| !t.is_empty()) {
        return Chunk::Text(t.to_string());
    }
    Chunk::Ignore
}

/// Take the secrets out of a prompt, unless the caller explicitly asked not to.
///
/// This sits at the command boundary rather than in whichever panel assembled
/// the prompt: a redaction the frontend performs is one a future caller
/// forgets. `ai_send` and `ai_preview` both go through here, which is what
/// makes the preview trustworthy - the inspector shows the same bytes the
/// request carries, because the same function produced them.
fn scrub(
    system: String,
    messages: Vec<AiMessage>,
    allow_secrets: Option<bool>,
) -> (String, Vec<AiMessage>, Vec<crate::redact::Hit>) {
    if allow_secrets.unwrap_or(false) {
        return (system, messages, Vec::new());
    }
    let mut redacted: Vec<crate::redact::Hit> = Vec::new();
    let (system, hits) = crate::redact::redact(&system);
    crate::redact::merge(&mut redacted, hits);
    let messages = messages
        .into_iter()
        .map(|m| {
            let (content, hits) = crate::redact::redact(&m.content);
            crate::redact::merge(&mut redacted, hits);
            AiMessage {
                role: m.role,
                content,
            }
        })
        .collect();
    (system, messages, redacted)
}

/// Exactly what a send would put on the wire, without sending it.
#[derive(Serialize)]
pub struct AiPreview {
    /// UTF-8 bytes of prompt text - the system message plus every turn. Not the
    /// whole HTTP body: the model id and the sampling knobs are a fixed
    /// overhead nobody needs a number for.
    pub bytes: usize,
    pub system: String,
    pub messages: Vec<AiMessage>,
    pub redacted: Vec<crate::redact::Hit>,
}

/// Show the user what a send would transmit, character for character.
///
/// Deliberately takes no vault key and reads nothing from disk: it transforms
/// the arguments it is handed and returns them. That is why it is safe to call
/// on every keystroke, and why it works with the vault locked.
#[tauri::command]
pub fn ai_preview(
    system: String,
    messages: Vec<AiMessage>,
    allow_secrets: Option<bool>,
) -> AiPreview {
    let (system, messages, redacted) = scrub(system, messages, allow_secrets);
    let bytes = system.len() + messages.iter().map(|m| m.content.len()).sum::<usize>();
    AiPreview {
        bytes,
        system,
        messages,
        redacted,
    }
}

/// Stream a completion. Emits `ai-delta-<id>` (text), `ai-thinking-<id>`,
/// `ai-done-<id>`, and `ai-error-<id>`.
///
/// Returns what redaction removed on the way out, so the panel can tell the
/// user what did *not* reach OpenRouter. `allow_secrets` is the per-send
/// override: absent or false means redact, which is what every caller that
/// doesn't think about it gets.
#[tauri::command]
pub async fn ai_send(
    app_handle: AppHandle,
    state: tauri::State<'_, crate::AppState>,
    request_id: String,
    system: String,
    messages: Vec<AiMessage>,
    allow_secrets: Option<bool>,
) -> Result<Vec<crate::redact::Hit>, String> {
    let key = { *state.vault_key.lock().unwrap() }.ok_or("Vault is locked")?;
    let config =
        load_config(&key).ok_or("The AI copilot isn't set up yet - add a key under Settings.")?;

    let (system, messages, redacted) = scrub(system, messages, allow_secrets);

    // Resolve credentials before spawning so auth errors surface immediately.
    let auth = resolve_auth(&config)?;
    let body = build_body(&config, &system, &messages);

    let cancel = Arc::new(AtomicBool::new(false));
    state
        .ai_cancels
        .lock()
        .unwrap()
        .insert(request_id.clone(), Arc::clone(&cancel));

    let cancels = Arc::clone(&state.ai_cancels);
    let id = request_id.clone();

    // ureq is blocking; keep it off the async runtime.
    tokio::task::spawn_blocking(move || {
        let finish = |ev: &str, payload: String| {
            app_handle.emit(&format!("{}-{}", ev, id), payload).ok();
            cancels.lock().unwrap().remove(&id);
        };

        let mut req = ureq::post(OPENROUTER_URL).set("content-type", "application/json");
        for (k, v) in &auth.headers {
            req = req.set(k, v);
        }

        let resp = match req.send_json(body) {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let detail = r.into_string().unwrap_or_default();
                finish("ai-error", friendly_http_error(code, &detail));
                return;
            }
            Err(e) => {
                finish("ai-error", format!("Could not reach the API: {e}"));
                return;
            }
        };

        let reader = BufReader::new(resp.into_reader());
        for line in reader.lines() {
            if cancel.load(Ordering::Relaxed) {
                finish("ai-done", String::new());
                return;
            }
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    finish("ai-error", format!("Stream ended unexpectedly: {e}"));
                    return;
                }
            };
            // SSE: we only care about the data payloads.
            let Some(data) = line.strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            // OpenAI-style terminator.
            if data == "[DONE]" {
                finish("ai-done", String::new());
                return;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
                continue;
            };
            match parse_chunk(&v) {
                Chunk::Text(t) => {
                    app_handle.emit(&format!("ai-delta-{}", id), t).ok();
                }
                Chunk::Thinking(t) => {
                    app_handle.emit(&format!("ai-thinking-{}", id), t).ok();
                }
                Chunk::Err(e) => {
                    finish("ai-error", e);
                    return;
                }
                Chunk::Ignore => {}
            }
        }
        // Fallback if the body ends without an explicit [DONE].
        finish("ai-done", String::new());
    });

    Ok(redacted)
}

/// Ask OpenRouter which models exist, so the UI never depends on a hardcoded
/// list that has gone stale.
#[tauri::command]
pub async fn ai_list_models(
    state: tauri::State<'_, crate::AppState>,
) -> Result<Vec<AiModel>, String> {
    let key = { *state.vault_key.lock().unwrap() }.ok_or("Vault is locked")?;
    let config = load_config(&key).ok_or("The AI copilot isn't set up yet.")?;
    let auth = resolve_auth(&config)?;

    tokio::task::spawn_blocking(move || {
        let mut req = ureq::get(OPENROUTER_MODELS_URL);
        for (k, v) in &auth.headers {
            req = req.set(k, v);
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                return Err(friendly_http_error(
                    code,
                    &r.into_string().unwrap_or_default(),
                ))
            }
            Err(e) => return Err(format!("Could not reach the API: {e}")),
        };
        let v: serde_json::Value = resp.into_json().map_err(|e| e.to_string())?;

        let mut models: Vec<AiModel> = v["data"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        let id = m["id"].as_str()?.to_string();
                        let label = m["name"].as_str().unwrap_or(&id).to_string();
                        Some(AiModel { id, label })
                    })
                    .collect()
            })
            .unwrap_or_default();
        // OpenRouter returns hundreds of models unordered; sort for a usable list.
        models.sort_by_key(|m| m.label.to_lowercase());
        Ok(models)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Friendlier text for the handful of statuses users actually hit.
fn friendly_http_error(code: u16, detail: &str) -> String {
    let api_msg = serde_json::from_str::<serde_json::Value>(detail)
        .ok()
        .and_then(|v| v["error"]["message"].as_str().map(str::to_string));
    match code {
        400 => api_msg.unwrap_or_else(|| "The API rejected the request.".to_string()),
        401 | 403 => format!(
            "Authentication failed - check your OpenRouter API key.{}",
            api_msg.map(|m| format!(" ({m})")).unwrap_or_default()
        ),
        404 => api_msg
            .unwrap_or_else(|| "Unknown model - pick a different one in Settings.".to_string()),
        429 => "Rate limited by the API. Wait a moment and retry.".to_string(),
        529 => "The API is overloaded right now. Try again shortly.".to_string(),
        _ => api_msg.unwrap_or_else(|| format!("API error {code}")),
    }
}

#[tauri::command]
pub fn ai_cancel(state: tauri::State<'_, crate::AppState>, request_id: String) {
    if let Some(flag) = state.ai_cancels.lock().unwrap().get(&request_id) {
        flag.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(content: &str) -> AiMessage {
        AiMessage {
            role: "user".into(),
            content: content.into(),
        }
    }

    /// The preview is only worth showing if it cannot drift from the request.
    /// Both go through `scrub`; this asserts they stay that way.
    #[test]
    fn preview_shows_exactly_what_a_send_would_carry() {
        let system = "context AKIAIOSFODNN7EXAMPLE".to_string();
        let messages = vec![msg("export DB_PASSWORD=hunter2"), msg("plain question")];

        let (want_system, want_messages, want_hits) = scrub(system.clone(), messages.clone(), None);
        let got = ai_preview(system, messages, None);

        assert_eq!(got.system, want_system);
        assert_eq!(
            got.messages.iter().map(|m| &m.content).collect::<Vec<_>>(),
            want_messages.iter().map(|m| &m.content).collect::<Vec<_>>()
        );
        assert_eq!(got.redacted, want_hits);
        assert!(!got.system.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!got.messages[0].content.contains("hunter2"));
    }

    #[test]
    fn preview_counts_the_bytes_it_shows() {
        let got = ai_preview("abc".into(), vec![msg("defg")], None);
        assert_eq!(got.bytes, 7);
        // Multi-byte characters are counted as the bytes they take on the wire.
        let got = ai_preview("é".into(), vec![], None);
        assert_eq!(got.bytes, 2);
    }

    #[test]
    fn the_override_leaves_the_prompt_untouched() {
        let secret = "export DB_PASSWORD=hunter2";
        let got = ai_preview(String::new(), vec![msg(secret)], Some(true));
        assert_eq!(got.messages[0].content, secret);
        assert!(got.redacted.is_empty());
    }

    #[test]
    fn absent_override_still_redacts() {
        // `None` is what every caller that never thought about it sends.
        let got = ai_preview(String::new(), vec![msg("export TOKEN=abc123")], None);
        assert!(!got.messages[0].content.contains("abc123"));
        assert_eq!(got.redacted.len(), 1);
    }

    fn cfg(key: &str) -> AiConfig {
        let mut api_keys = HashMap::new();
        if !key.is_empty() {
            api_keys.insert(PROVIDER_OPENROUTER.to_string(), key.to_string());
        }
        AiConfig {
            provider: PROVIDER_OPENROUTER.to_string(),
            api_keys,
            models: HashMap::new(),
            effort: DEFAULT_EFFORT.to_string(),
        }
    }

    #[test]
    fn view_never_exposes_a_key() {
        let view = cfg("sk-or-secret").view();
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("sk-or-secret"));
        assert!(view.has_api_key);
        assert!(view.configured);
    }

    #[test]
    fn api_key_is_required_to_be_configured() {
        assert!(!cfg("").view().configured);
        assert!(cfg("sk-or-x").view().configured);
    }

    #[test]
    fn model_falls_back_to_the_default() {
        assert_eq!(cfg("k").model(), DEFAULT_MODEL);
        let mut c = cfg("k");
        c.models
            .insert(PROVIDER_OPENROUTER.into(), "openai/gpt-4o".into());
        assert_eq!(c.model(), "openai/gpt-4o");
    }

    #[test]
    fn auth_uses_bearer_and_attribution() {
        let auth = resolve_auth(&cfg("sk-or-x")).unwrap();
        assert_eq!(auth.headers[0].0, "authorization");
        assert_eq!(auth.headers[0].1, "Bearer sk-or-x");
        assert!(auth.headers.iter().any(|(k, _)| k == "x-title"));
    }

    #[test]
    fn missing_key_is_a_clear_error_not_a_panic() {
        assert!(resolve_auth(&cfg("")).is_err());
    }

    #[test]
    fn body_prepends_system_and_requests_reasoning() {
        let body = build_body(
            &cfg("k"),
            "sys",
            &[AiMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
        );
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][0]["content"], "sys");
        assert_eq!(body["messages"][1]["role"], "user");
        assert_eq!(body["stream"], true);
        assert_eq!(body["reasoning"]["effort"], "medium");
    }

    #[test]
    fn body_omits_reasoning_for_non_effort_values() {
        let mut c = cfg("k");
        c.effort = "xhigh".into();
        let body = build_body(
            &c,
            "",
            &[AiMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
        );
        assert!(body.get("reasoning").is_none());
        // No system message means no leading system entry.
        assert_eq!(body["messages"][0]["role"], "user");
    }

    #[test]
    fn parses_content_and_reasoning_deltas() {
        let text = serde_json::json!({
            "choices": [{ "delta": { "content": "hello" } }]
        });
        assert_eq!(parse_chunk(&text), Chunk::Text("hello".into()));

        let reasoning = serde_json::json!({
            "choices": [{ "delta": { "reasoning": "hmm" } }]
        });
        assert_eq!(parse_chunk(&reasoning), Chunk::Thinking("hmm".into()));

        let empty = serde_json::json!({ "choices": [{ "delta": {} }] });
        assert_eq!(parse_chunk(&empty), Chunk::Ignore);
    }

    #[test]
    fn api_errors_surface() {
        let err = serde_json::json!({ "error": { "message": "bad key" } });
        assert_eq!(parse_chunk(&err), Chunk::Err("bad key".into()));
    }
}
