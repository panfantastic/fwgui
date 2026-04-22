use axum::{
    Json,
    extract::{Path, Query, State},
    response::sse::{Event, KeepAlive, Sse},
};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::{mpsc, oneshot};

use crate::nft;
use crate::state::{ActiveBreakpoint, AppState, ChangeMode, FwState, StagedChange};

#[derive(Deserialize)]
pub struct SaveConfigForm {
    content: String,
}

#[derive(Deserialize)]
pub struct StageForm {
    mode: String,
    content: String,
}

#[derive(Deserialize)]
pub struct ValidateForm {
    content: String,
}

#[derive(Serialize)]
pub struct ActionResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notice: Option<String>,
}

#[derive(Serialize)]
pub struct ValidateResponse {
    ok: bool,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct BreakpointRequest {
    line: usize,
}

#[derive(Serialize)]
pub struct BreakpointResponse {
    ok: bool,
    error: Option<String>,
    log_handle: Option<u64>,
}

#[derive(Serialize)]
pub struct BreakpointInfo {
    line: usize,
    table_family: String,
    table_name: String,
    chain_name: String,
    rule_handle: u64,
    log_handle: u64,
}

#[derive(Serialize)]
struct DefineInfo {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct SidebarState {
    interfaces: Vec<String>,
    defines: Vec<DefineInfo>,
    sets: Vec<String>,
}

#[derive(Serialize)]
struct ConfigState {
    mode: String,
    saved_path: String,
}

#[derive(Serialize)]
pub struct AppStateResponse {
    phase: String,
    live_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    live_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    edit_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    edit_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    staged_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    staged_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deadline_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sidebar: Option<SidebarState>,
    config: ConfigState,
}

#[derive(Deserialize)]
pub struct StateQuery {
    mode: Option<String>,
}

/// Bridges an mpsc::Receiver<String> into a Stream<Item = Result<Event, Infallible>>.
struct LogEventStream(mpsc::Receiver<String>);

impl Stream for LogEventStream {
    type Item = Result<Event, Infallible>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.poll_recv(cx) {
            Poll::Ready(Some(line)) => Poll::Ready(Some(Ok(Event::default().data(line)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn validate(Json(form): Json<ValidateForm>) -> Json<ValidateResponse> {
    match nft::validate_script(&form.content) {
        Ok(()) => Json(ValidateResponse { ok: true, error: None }),
        Err(e) => Json(ValidateResponse { ok: false, error: Some(e.to_string()) }),
    }
}

#[derive(Deserialize)]
pub struct GraphDotQuery {
    hide: Option<String>,
}

pub async fn graph_dot(Query(q): Query<GraphDotQuery>) -> axum::response::Response {
    use axum::http::StatusCode;
    let hidden: std::collections::HashSet<String> = q.hide.as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    match crate::graph::build_dot(&hidden) {
        Ok((dot, families)) => axum::response::Response::builder()
            .header(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header("X-Graph-Families", families.join(","))
            .header("Access-Control-Expose-Headers", "X-Graph-Families")
            .body(axum::body::Body::from(dot))
            .unwrap(),
        Err(e) => axum::response::Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(axum::body::Body::from(e))
            .unwrap(),
    }
}

pub async fn stage(
    State(state): State<Arc<AppState>>,
    Json(form): Json<StageForm>,
) -> Json<ActionResponse> {
    if form.content.trim().is_empty() {
        return Json(ActionResponse { ok: false, error: Some("Content cannot be empty".into()), notice: None });
    }

    let (mode, content, saved_config) = if form.mode == "saved_incremental" {
        let original = form.content;
        let patch = nft::build_saved_config_patch(&original);
        if patch.trim().is_empty() {
            return Json(ActionResponse { ok: false, error: Some("No tables or defines found in saved config".into()), notice: None });
        }
        (ChangeMode::Patch, patch, Some(original))
    } else {
        let m = match form.mode.as_str() {
            "full" => ChangeMode::Full,
            "patch" => ChangeMode::Patch,
            _ => return Json(ActionResponse { ok: false, error: Some("Invalid mode".into()), notice: None }),
        };
        (m, form.content, None)
    };

    if let Err(e) = nft::validate_script(&content) {
        return Json(ActionResponse { ok: false, error: Some(format!("Validation failed: {e}")), notice: None });
    }
    let mut fw = state.fw.lock().unwrap();
    if matches!(*fw, FwState::Promoting { .. }) {
        return Json(ActionResponse { ok: false, error: Some("Cannot stage a change while promotion is pending".into()), notice: None });
    }
    *fw = FwState::Staged(StagedChange { mode, content, saved_config });
    Json(ActionResponse { ok: true, error: None, notice: Some("Change staged successfully".into()) })
}

pub async fn promote(State(state): State<Arc<AppState>>) -> Json<ActionResponse> {
    let change = {
        let fw = state.fw.lock().unwrap();
        match &*fw {
            FwState::Staged(c) => c.clone(),
            FwState::Idle => return Json(ActionResponse { ok: false, error: Some("No staged change to promote".into()), notice: None }),
            FwState::Promoting { .. } => return Json(ActionResponse { ok: false, error: Some("Already promoting a change".into()), notice: None }),
        }
    };

    let previous_text = match nft::get_ruleset_text() {
        Ok(t) => t,
        Err(e) => return Json(ActionResponse { ok: false, error: Some(format!("Could not snapshot current ruleset: {e}")), notice: None }),
    };

    let apply_result = match change.mode {
        ChangeMode::Full => nft::apply_full(&change.content),
        ChangeMode::Patch => nft::apply_patch(&change.content),
    };
    if let Err(e) = apply_result {
        return Json(ActionResponse { ok: false, error: Some(format!("Apply failed: {e}")), notice: None });
    }

    let rollback_secs = state.config.rollback_secs;
    let deadline = Instant::now() + Duration::from_secs(rollback_secs);
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    let state_clone = Arc::clone(&state);

    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(rollback_secs)) => {
                // Atomically claim Promoting state before rolling back.
                // If acknowledge already transitioned to Idle, prev will be None and we skip.
                let prev = {
                    let mut fw = state_clone.fw.lock().unwrap();
                    match std::mem::replace(&mut *fw, FwState::Idle) {
                        FwState::Promoting { previous_text, .. } => Some(previous_text),
                        other => { *fw = other; None }
                    }
                };
                if let Some(prev) = prev {
                    tracing::warn!("rollback timer expired — reverting");
                    let result = tokio::task::spawn_blocking(move || nft::restore(&prev)).await;
                    match result {
                        Ok(Ok(())) => tracing::info!("rollback succeeded"),
                        Ok(Err(e)) => tracing::error!("rollback failed: {e}"),
                        Err(e) => tracing::error!("rollback task panicked: {e}"),
                    }
                }
            }
            _ = cancel_rx => {
                tracing::info!("promotion acknowledged — rollback cancelled");
            }
        }
    });

    let mut fw = state.fw.lock().unwrap();
    *fw = FwState::Promoting { change, previous_text, deadline, cancel_tx };
    Json(ActionResponse { ok: true, error: None, notice: Some("Change promoted — acknowledge before the timer expires".into()) })
}

pub async fn acknowledge(State(state): State<Arc<AppState>>) -> Json<ActionResponse> {
    let mut fw = state.fw.lock().unwrap();
    match &*fw {
        FwState::Promoting { .. } => {}
        _ => return Json(ActionResponse { ok: false, error: Some("Not in a promoting state".into()), notice: None }),
    }
    let (cancel_tx, saved_config) = match std::mem::replace(&mut *fw, FwState::Idle) {
        FwState::Promoting { cancel_tx, change, .. } => (cancel_tx, change.saved_config),
        _ => unreachable!(),
    };
    drop(fw);
    let _ = cancel_tx.send(());

    if let Some(config) = saved_config {
        match nft::write_saved_config(
            &state.config.saved_config_path,
            &config,
            &state.config.backup_dir,
        ) {
            Ok(()) => return Json(ActionResponse { ok: true, error: None, notice: Some("Change acknowledged — config saved to disk".into()) }),
            Err(e) => {
                tracing::error!("disk save failed after acknowledge: {e}");
                return Json(ActionResponse { ok: false, error: Some(format!("Change is live but disk save failed: {e}")), notice: None });
            }
        }
    }

    Json(ActionResponse { ok: true, error: None, notice: Some("Change acknowledged — rollback cancelled".into()) })
}

pub async fn clear(State(state): State<Arc<AppState>>) -> Json<ActionResponse> {
    let mut fw = state.fw.lock().unwrap();
    match &*fw {
        FwState::Staged(_) => {
            *fw = FwState::Idle;
            Json(ActionResponse { ok: true, error: None, notice: Some("Staged change cleared".into()) })
        }
        FwState::Promoting { .. } => {
            Json(ActionResponse { ok: false, error: Some("Cannot clear while promotion is pending — acknowledge or wait for rollback".into()), notice: None })
        }
        FwState::Idle => Json(ActionResponse { ok: true, error: None, notice: None }),
    }
}

pub async fn save_config(
    State(state): State<Arc<AppState>>,
    Json(form): Json<SaveConfigForm>,
) -> Json<ActionResponse> {
    if form.content.trim().is_empty() {
        return Json(ActionResponse { ok: false, error: Some("Content cannot be empty".into()), notice: None });
    }
    match nft::write_saved_config(
        &state.config.saved_config_path,
        &form.content,
        &state.config.backup_dir,
    ) {
        Ok(()) => Json(ActionResponse { ok: true, error: None, notice: Some("Config saved to disk".into()) }),
        Err(e) => Json(ActionResponse { ok: false, error: Some(format!("Save failed: {e}")), notice: None }),
    }
}

pub async fn api_state(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StateQuery>,
) -> Json<AppStateResponse> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let is_saved = q.mode.as_deref() == Some("saved");

    let (live_text, live_error) = match nft::get_ruleset_annotated() {
        Ok(t) => (t, None),
        Err(e) => match nft::get_ruleset_text() {
            Ok(t) => (t, Some(e.to_string())),
            Err(e2) => (String::new(), Some(e2.to_string())),
        },
    };

    let config = ConfigState {
        mode: if is_saved { "saved".into() } else { "running".into() },
        saved_path: state.config.saved_config_path.clone(),
    };

    let fw = state.fw.lock().unwrap();
    let resp = match &*fw {
        FwState::Idle => {
            let (edit_text, edit_error) = if is_saved {
                match nft::read_saved_config(&state.config.saved_config_path) {
                    Ok(t) => (t, None),
                    Err(e) => (String::new(), Some(e.to_string())),
                }
            } else {
                (live_text.clone(), live_error.clone())
            };
            let sidebar = SidebarState {
                interfaces: nft::get_interfaces(),
                defines: nft::parse_defines(&edit_text)
                    .into_iter()
                    .map(|(name, value)| DefineInfo { name, value })
                    .collect(),
                sets: nft::parse_sets(&edit_text),
            };
            AppStateResponse {
                phase: "editing".into(),
                live_text,
                live_error,
                edit_text: Some(edit_text),
                edit_error,
                staged_text: None,
                staged_mode: None,
                previous_text: None,
                deadline_ms: None,
                sidebar: Some(sidebar),
                config,
            }
        }
        FwState::Staged(change) => AppStateResponse {
            phase: "staged".into(),
            live_text,
            live_error,
            edit_text: None,
            edit_error: None,
            staged_text: Some(change.content.clone()),
            staged_mode: Some(change.mode.to_string()),
            previous_text: None,
            deadline_ms: None,
            sidebar: None,
            config,
        },
        FwState::Promoting { change, previous_text, deadline, .. } => {
            let now_sys = SystemTime::now();
            let now_inst = Instant::now();
            let until_deadline = deadline.saturating_duration_since(now_inst);
            let deadline_ms = now_sys
                .checked_add(until_deadline)
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64);
            AppStateResponse {
                phase: "promoting".into(),
                live_text,
                live_error,
                edit_text: None,
                edit_error: None,
                staged_text: Some(change.content.clone()),
                staged_mode: Some(change.mode.to_string()),
                previous_text: Some(previous_text.clone()),
                deadline_ms,
                sidebar: None,
                config,
            }
        }
    };
    drop(fw);
    Json(resp)
}


// ---------------------------------------------------------------------------
// Breakpoint handlers
// ---------------------------------------------------------------------------

pub async fn breakpoint_set(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BreakpointRequest>,
) -> Json<BreakpointResponse> {
    let annotated = match nft::get_ruleset_annotated() {
        Ok(t) => t,
        Err(e) => return Json(BreakpointResponse { ok: false, error: Some(e.to_string()), log_handle: None }),
    };
    let handles = nft::parse_ruleset_handles(&annotated);
    let rule = match handles.get(&req.line) {
        Some(r) => r.clone(),
        None => return Json(BreakpointResponse {
            ok: false,
            error: Some(format!("no rule at line {}", req.line)),
            log_handle: None,
        }),
    };
    let log_handle = match nft::insert_breakpoint(&rule, &req.line.to_string()) {
        Ok(h) => h,
        Err(e) => return Json(BreakpointResponse { ok: false, error: Some(e.to_string()), log_handle: None }),
    };
    state.breakpoints.lock().unwrap().insert(req.line, ActiveBreakpoint { rule });
    Json(BreakpointResponse { ok: true, error: None, log_handle: Some(log_handle) })
}

pub async fn breakpoint_clear(
    State(state): State<Arc<AppState>>,
    Path(line): Path<usize>,
) -> Json<ValidateResponse> {
    let rule = state.breakpoints.lock().unwrap()
        .get(&line).map(|bp| bp.rule.clone());
    match rule {
        None => Json(ValidateResponse { ok: false, error: Some(format!("no breakpoint at line {line}")) }),
        Some(rule) => match nft::remove_breakpoint(&rule) {
            Ok(()) => {
                state.breakpoints.lock().unwrap().remove(&line);
                Json(ValidateResponse { ok: true, error: None })
            },
            Err(e) => Json(ValidateResponse { ok: false, error: Some(e.to_string()) }),
        }
    }
}

pub async fn breakpoints_list(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<BreakpointInfo>> {
    let bps = state.breakpoints.lock().unwrap();
    let mut list: Vec<BreakpointInfo> = bps.iter().map(|(&line, bp)| BreakpointInfo {
        line,
        table_family: bp.rule.table_family.clone(),
        table_name: bp.rule.table_name.clone(),
        chain_name: bp.rule.chain_name.clone(),
        rule_handle: bp.rule.handle,
        log_handle: bp.rule.handle,
    }).collect();
    list.sort_by_key(|b| b.line);
    Json(list)
}

/// SSE endpoint that streams kernel log lines containing `fwgui-bp-`.
/// Reads /dev/kmsg directly (avoids the CAP_SYSLOG ioctl that dmesg uses),
/// falling back to `journalctl -f -k` if /dev/kmsg is not accessible.
/// On connect, writes a self-test marker to /dev/kmsg to confirm the pipeline
/// end-to-end; if nf_log modules are missing the marker still appears but
/// breakpoint packets won't.
pub async fn log_stream() -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let (tx, rx) = mpsc::channel::<String>(64);
    let _ = tx.try_send("● Connecting to kernel log...".to_string());

    tokio::spawn(async move {
        match tokio::fs::OpenOptions::new().read(true).open("/dev/kmsg").await {
            Ok(mut file) => {
                // Seek to end so we skip the existing ring buffer, then inject a
                // self-test marker — if it comes back we know the full pipeline works.
                let _ = file.seek(std::io::SeekFrom::End(0)).await;
                let _ = std::fs::write("/dev/kmsg",
                    b"<6>fwgui-bp-test: monitoring active (if nf_log modules missing, only this line appears)\n");

                let mut lines = BufReader::new(file).lines();
                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            if line.starts_with(' ') { continue; } // metadata continuation
                            // /dev/kmsg format: "priority,seq,ts,flag;message"
                            let msg = line.splitn(2, ';').nth(1).unwrap_or(&line);
                            if msg.contains("fwgui-bp-") {
                                let label = msg.splitn(2, ':').next().unwrap_or("").trim();
                                let body  = msg.splitn(2, ':').nth(1).unwrap_or(msg).trim();
                                let formatted = format!("[{}]  {}", label, nft::format_log_line(body));
                                if tx.send(formatted).await.is_err() { break; }
                            }
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
            }
            Err(kmsg_err) => {
                // Fall back to journalctl.
                let child = tokio::process::Command::new("journalctl")
                    .args(["-f", "-k", "--output=cat"])
                    .stdout(Stdio::piped())
                    .kill_on_drop(true)
                    .spawn();
                match child {
                    Ok(mut c) => {
                        let _ = tx.send("● Connected via journalctl — waiting for fwgui-bp- events...".to_string()).await;
                        if let Some(stdout) = c.stdout.take() {
                            let mut lines = BufReader::new(stdout).lines();
                            while let Ok(Some(line)) = lines.next_line().await {
                                if line.contains("fwgui-bp-") {
                                    let label = line.splitn(2, ':').next().unwrap_or("").trim();
                                    let body  = line.splitn(2, ':').nth(1).unwrap_or(&line).trim();
                                    let formatted = format!("[{}]  {}", label, nft::format_log_line(body));
                                    if tx.send(formatted).await.is_err() { break; }
                                }
                            }
                        }
                    }
                    Err(jctl_err) => {
                        let _ = tx.send(format!(
                            "ERROR: cannot read kernel log — /dev/kmsg: {kmsg_err} | journalctl: {jctl_err}\n\
                             Hint: ensure nf_log_inet (or nf_log_ipv4/nf_log_ipv6) is loaded:\n\
                             modprobe nf_log_inet"
                        )).await;
                    }
                }
            }
        }
    });
    Sse::new(LogEventStream(rx)).keep_alive(KeepAlive::default())
}

