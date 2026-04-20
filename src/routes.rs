use axum::{
    Json,
    extract::{Path, Query, State},
    response::{Html, Redirect},
    response::sse::{Event, KeepAlive, Sse},
    Form,
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

struct SidebarData {
    interfaces: Vec<String>,
    defines: Vec<(String, String)>,
    sets: Vec<String>,
}

#[derive(Clone, Copy, PartialEq)]
enum EditMode { Running, Saved }

#[derive(Deserialize)]
pub struct IndexQuery {
    error: Option<String>,
    notice: Option<String>,
    mode: Option<String>,
}

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

pub async fn validate(Form(form): Form<ValidateForm>) -> Json<ValidateResponse> {
    match nft::validate_script(&form.content) {
        Ok(()) => Json(ValidateResponse { ok: true, error: None }),
        Err(e) => Json(ValidateResponse { ok: false, error: Some(e.to_string()) }),
    }
}

pub async fn index(
    State(state): State<Arc<AppState>>,
    Query(q): Query<IndexQuery>,
) -> Html<String> {
    let edit_mode = if q.mode.as_deref() == Some("saved") { EditMode::Saved } else { EditMode::Running };

    // Running config uses annotated output (with # handle N) so gutter breakpoints map correctly.
    let (live_text, live_error) = match nft::get_ruleset_annotated() {
        Ok(t) => (t, None),
        Err(e) => match nft::get_ruleset_text() {
            Ok(t) => (t, Some(e.to_string())),
            Err(e2) => (String::new(), Some(e2.to_string())),
        },
    };

    let fw = state.fw.lock().unwrap();
    let body = match &*fw {
        FwState::Idle => {
            let (edit_text, edit_error) = match edit_mode {
                EditMode::Running => (live_text.clone(), live_error.clone()),
                EditMode::Saved => match nft::read_saved_config(&state.config.saved_config_path) {
                    Ok(t) => (t, None),
                    Err(e) => (String::new(), Some(e.to_string())),
                },
            };
            let sidebar = SidebarData {
                interfaces: nft::get_interfaces(),
                defines: nft::parse_defines(&edit_text),
                sets: nft::parse_sets(&edit_text),
            };
            render_editing(&edit_text, edit_error.as_deref(), &sidebar, edit_mode, &state.config.saved_config_path)
        }
        FwState::Staged(change) => render_staged(change, &live_text),
        FwState::Promoting { change, deadline, previous_text, .. } => {
            render_promoting(change, previous_text, deadline.saturating_duration_since(Instant::now()))
        }
    };
    drop(fw);

    let error_html = q.error.as_deref()
        .map(|e| format!("<div class='msg error'>{}</div>", he(e)))
        .unwrap_or_default();
    let notice_html = q.notice.as_deref()
        .map(|n| format!("<div class='msg notice'>{}</div>", he(n)))
        .unwrap_or_default();

    Html(page(&format!("{error_html}{notice_html}{body}")))
}

pub async fn stage(
    State(state): State<Arc<AppState>>,
    Form(form): Form<StageForm>,
) -> Redirect {
    if form.content.trim().is_empty() {
        return redirect_error("Content cannot be empty");
    }

    // saved_incremental: build a per-table patch; keep original for disk write on acknowledge.
    let (mode, content, saved_config) = if form.mode == "saved_incremental" {
        let original = form.content;
        let patch = nft::build_saved_config_patch(&original);
        if patch.trim().is_empty() {
            return redirect_error("No tables or defines found in saved config");
        }
        (ChangeMode::Patch, patch, Some(original))
    } else {
        let m = match form.mode.as_str() {
            "full" => ChangeMode::Full,
            "patch" => ChangeMode::Patch,
            _ => return redirect_error("Invalid mode"),
        };
        (m, form.content, None)
    };

    if let Err(e) = nft::validate_script(&content) {
        return redirect_error(&format!("Validation failed: {e}"));
    }
    let mut fw = state.fw.lock().unwrap();
    if matches!(*fw, FwState::Promoting { .. }) {
        return redirect_error("Cannot stage a change while promotion is pending");
    }
    *fw = FwState::Staged(StagedChange { mode, content, saved_config });
    redirect_notice("Change staged successfully")
}

pub async fn promote(State(state): State<Arc<AppState>>) -> Redirect {
    let change = {
        let fw = state.fw.lock().unwrap();
        match &*fw {
            FwState::Staged(c) => c.clone(),
            FwState::Idle => return redirect_error("No staged change to promote"),
            FwState::Promoting { .. } => return redirect_error("Already promoting a change"),
        }
    };

    let previous_text = match nft::get_ruleset_text() {
        Ok(t) => t,
        Err(e) => return redirect_error(&format!("Could not snapshot current ruleset: {e}")),
    };

    let apply_result = match change.mode {
        ChangeMode::Full => nft::apply_full(&change.content),
        ChangeMode::Patch => nft::apply_patch(&change.content),
    };
    if let Err(e) = apply_result {
        return redirect_error(&format!("Apply failed: {e}"));
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
    redirect_notice("Change promoted — acknowledge before the timer expires")
}

pub async fn acknowledge(State(state): State<Arc<AppState>>) -> Redirect {
    let mut fw = state.fw.lock().unwrap();
    match &*fw {
        FwState::Promoting { .. } => {}
        _ => return redirect_error("Not in a promoting state"),
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
            Ok(()) => return redirect_notice("Change acknowledged — config saved to disk"),
            Err(e) => {
                tracing::error!("disk save failed after acknowledge: {e}");
                return Redirect::to(&format!(
                    "/?error={}",
                    url_encode(&format!("Change is live but disk save failed: {e}"))
                ));
            }
        }
    }

    redirect_notice("Change acknowledged — rollback cancelled")
}

pub async fn clear(State(state): State<Arc<AppState>>) -> Redirect {
    let mut fw = state.fw.lock().unwrap();
    match &*fw {
        FwState::Staged(_) => {
            *fw = FwState::Idle;
            redirect_notice("Staged change cleared")
        }
        FwState::Promoting { .. } => {
            redirect_error("Cannot clear while promotion is pending — acknowledge or wait for rollback")
        }
        FwState::Idle => Redirect::to("/"),
    }
}

pub async fn save_config(
    State(state): State<Arc<AppState>>,
    Form(form): Form<SaveConfigForm>,
) -> Redirect {
    if form.content.trim().is_empty() {
        return Redirect::to("/?mode=saved&error=Content+cannot+be+empty");
    }
    match nft::write_saved_config(
        &state.config.saved_config_path,
        &form.content,
        &state.config.backup_dir,
    ) {
        Ok(()) => Redirect::to("/?mode=saved&notice=Config+saved+to+disk"),
        Err(e) => Redirect::to(&format!(
            "/?mode=saved&error={}",
            url_encode(&format!("Save failed: {e}"))
        )),
    }
}

// ---------------------------------------------------------------------------
// Page rendering
// ---------------------------------------------------------------------------

fn page(body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>fwgui</title>
<style>
  body {{ font-family: monospace; max-width: 1200px; margin: 2em auto; padding: 0 1em; background: #fafafa; }}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: .25em; }}
  h2 {{ border-bottom: 1px solid #aaa; padding-bottom: .15em; margin-top: 1.5em; }}
  h3 {{ margin-top: 1em; color: #444; }}
  pre {{ background: #f0f0f0; padding: 1em; overflow-x: auto; white-space: pre-wrap; border: 1px solid #ddd; margin: 0; }}
  select {{ margin-bottom: .5em; padding: .25em; }}
  button {{ padding: .4em .9em; margin: .2em; cursor: pointer; font-size: 1em; font-family: inherit; }}
  .btn-danger  {{ background: #b00; color: #fff; border: 1px solid #800; }}
  .btn-safe    {{ background: #060; color: #fff; border: 1px solid #030; }}
  .btn-neutral {{ background: #e0e0e0; border: 1px solid #aaa; }}
  .msg {{ padding: .5em .75em; margin: .75em 0; border-radius: 3px; }}
  .error  {{ background: #fdd; border: 1px solid #c00; }}
  .notice {{ background: #dfd; border: 1px solid #090; }}
  .warn   {{ background: #ffe; border: 1px solid #990; }}
  details {{ margin: .5em 0; }}
  details summary {{ cursor: pointer; color: #555; padding: .25em 0; }}
  details[open] summary {{ margin-bottom: .5em; }}
  .diff-view {{ background: #fff; border: 1px solid #ddd; padding: .5em 0;
                overflow-x: auto; font-family: monospace; font-size: .9em; line-height: 1.5; }}
  .diff-view span {{ display: block; white-space: pre; padding: 0 1em; }}
  .d-add {{ background: #e6ffed; color: #22863a; }}
  .d-del {{ background: #ffeef0; color: #cb2431; }}
  .d-eq  {{ color: #999; }}
  .d-none {{ color: #aaa; font-style: italic; padding: .5em 1em; }}
  .d-fold {{ margin: 0; border-top: 1px solid #eee; border-bottom: 1px solid #eee; }}
  .d-fold summary {{ display: block; padding: 2px 1em; cursor: pointer; color: #0969da;
                     background: #f6f8fa; font-size: .85em; user-select: none; list-style: none; }}
  .d-fold summary::-webkit-details-marker {{ display: none; }}
  .d-fold[open] summary {{ border-bottom: 1px solid #eee; margin-bottom: 0; }}
  #countdown {{ font-size: 1.6em; font-weight: bold; color: #b00; }}
  #validate-result {{ margin-top: .5em; min-height: 1.5em; }}
  .actions {{ margin-top: .75em; display: flex; gap: .5em; align-items: center; flex-wrap: wrap; }}
  .btn-sm {{ font-size: .8em; padding: .2em .4em; }}
  .log-controls {{ margin: .25em 0; display: flex; gap: .25em; flex-wrap: wrap; align-items: center; }}
  .log-controls label {{ font-size: .8em; color: #555; }}
  .log-controls input[type="number"] {{ width: 3.5em; font-size: 1em; padding: .1em .2em; }}
  .form-btns {{ margin: .5em 0; display: flex; gap: .25em; align-items: center; flex-wrap: wrap; }}
  #monitor-view {{ padding: .5em 1em; }}
  #monitor-view h2 {{ margin-top: .25em; }}
  .sb-help {{ list-style: none; padding: 0; margin: .25em 0; }}
  .sb-help li + li {{ margin-top: .4em; }}
  .hint {{ font-size: .8em; color: #888; margin: .3em 0; }}
  .mode-hint {{ margin: .2em 0 .4em; font-size: .85em; color: #555; }}
  .staged-full {{ margin-top: .75em; }}
  .save-inline {{ display: inline; margin-left: .25em; }}
  .mode-tabs {{ display: flex; margin-bottom: 1em; border-bottom: 2px solid #ccc; }}
  .tab-btn {{ padding: .4em 1.2em; text-decoration: none; color: #555; border: 1px solid transparent;
              border-bottom: none; margin: 0 0 -2px; border-radius: 3px 3px 0 0; background: transparent; }}
  .tab-btn.active {{ color: #000; background: #fff; border-color: #ccc; border-bottom-color: #fff; font-weight: bold; }}
  .tab-btn:hover:not(.active) {{ background: #f0f0f0; color: #333; }}
  .editor-layout {{ display: grid; grid-template-columns: 1fr 220px; gap: 1em; align-items: start; }}
  .editor-layout-bp {{ grid-template-columns: 200px 1fr 220px; }}
  .log-panel {{ border: 1px solid #ddd; border-radius: 3px; background: #fafafa; padding: .5em .75em;
                font-size: .85em; position: sticky; top: 1em; }}
  .log-panel h4 {{ margin: 0 0 .4em; color: #333; border-bottom: 1px solid #eee; padding-bottom: .1em; font-size: .95em; }}
  #log-output {{ height: 340px; overflow-y: auto; background: #111; color: #9f9; border-radius: 2px;
                 padding: .4em; margin-top: .4em; font-size: .8em;
                 resize: vertical; min-height: 80px; }}
  .log-line {{ white-space: pre-wrap; word-break: break-all; padding: 1px 0; border-bottom: 1px solid #222; }}
  .bp-marker {{ color: #c00; cursor: pointer; font-size: 1em; line-height: 1; padding: 0 2px; }}
  .bp-marker:hover {{ color: #f00; }}
  .bp-empty-marker {{ display: inline-block; width: .8em; cursor: pointer; padding: 0 2px; }}
  .bp-empty-marker:hover::after {{ content: '○'; color: #aaa; }}
  .sidebar {{ border: 1px solid #ddd; border-radius: 3px; background: #fafafa; padding: .5em .75em;
              font-size: .85em; position: sticky; top: 1em; }}
  .sidebar h4 {{ margin: .4em 0 .2em; color: #333; border-bottom: 1px solid #eee;
                 padding-bottom: .1em; font-size: .95em; }}
  .sidebar ul {{ margin: .2em 0; padding: 0 0 0 .75em; }}
  .sidebar li {{ padding: .1em 0; }}
  .sb-item {{ background: none; border: none; padding: 0; cursor: pointer; color: #0969da;
               font-family: monospace; font-size: 1em; text-align: left; }}
  .sb-item:hover {{ text-decoration: underline; }}
  .sb-empty {{ color: #aaa; font-style: italic; margin: .2em 0; }}
  .cm-tooltip {{ z-index: 100; }}
  .nft-tooltip {{ background: #1e293b; color: #f1f5f9; border-radius: 4px; padding: .4em .65em;
                  font-size: .82em; max-width: 300px; line-height: 1.4; }}
  .nft-tooltip strong {{ color: #7dd3fc; }}
  #editor {{ height: 420px; border: 1px solid #ccc; border-radius: 2px; font-size: .9em; }}
  #editor .cm-editor {{ height: 100%; }}
  #editor .cm-scroller {{ overflow: auto; }}
  .cm-err-line {{ background: #fdd !important; }}
  .cm-line.cm-diff-add {{ background: rgba(34,134,58,.12) !important; }}
  .cm-diff-del {{ display: block; height: 3px; background: #cb2431; border-radius: 1px; margin: 1px 0; }}
</style>
{diff_js}
</head>
<body>
<h1>fwgui</h1>
{body}
</body>
</html>"#,
        diff_js = DIFF_JS,
    )
}

// Shared diff algorithm — included once per page, used by all states.
const DIFF_JS: &str = r#"<script>
function lcsTable(a, b) {
    var m = a.length, n = b.length;
    var c = [];
    for (var i = 0; i <= m; i++) { c.push(new Array(n + 1).fill(0)); }
    for (var i = 1; i <= m; i++)
        for (var j = 1; j <= n; j++)
            c[i][j] = a[i-1] === b[j-1] ? c[i-1][j-1] + 1 : Math.max(c[i-1][j], c[i][j-1]);
    return c;
}

function normLine(l) { return l.replace(/\t/g, '    ').replace(/\s+$/, ''); }
function computeDiff(origText, editText) {
    var a = origText === '' ? [] : origText.split('\n').map(normLine);
    var b = editText === '' ? [] : editText.split('\n').map(normLine);
    var c = lcsTable(a, b);
    var ops = [];
    var i = a.length, j = b.length;
    while (i > 0 || j > 0) {
        if (i > 0 && j > 0 && a[i-1] === b[j-1]) {
            ops.unshift({t:'=', l:a[i-1]}); i--; j--;
        } else if (j > 0 && (i === 0 || c[i][j-1] >= c[i-1][j])) {
            ops.unshift({t:'+', l:b[j-1]}); j--;
        } else {
            ops.unshift({t:'-', l:a[i-1]}); i--;
        }
    }
    return ops;
}

function escHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function renderDiff(ops, el) {
    var CONTEXT = 3;
    var changed = ops.some(function(o) { return o.t !== '='; });
    if (ops.length === 0 || !changed) {
        el.innerHTML = '<span class="d-none">No changes.</span>';
        return;
    }
    // Mark which lines should be shown inline vs collapsed.
    var show = new Array(ops.length).fill(false);
    for (var i = 0; i < ops.length; i++) {
        if (ops[i].t !== '=') {
            var lo = Math.max(0, i - CONTEXT), hi = Math.min(ops.length - 1, i + CONTEXT);
            for (var k = lo; k <= hi; k++) show[k] = true;
        }
    }
    var html = '', i = 0;
    while (i < ops.length) {
        if (show[i]) {
            var e = escHtml(ops[i].l);
            if (ops[i].t === '+') html += '<span class="d-add">+ ' + e + '</span>';
            else if (ops[i].t === '-') html += '<span class="d-del">- ' + e + '</span>';
            else html += '<span class="d-eq">  ' + e + '</span>';
            i++;
        } else {
            var j = i;
            while (j < ops.length && !show[j]) j++;
            var n = j - i;
            html += '<details class="d-fold"><summary>' + n + ' unchanged line' + (n === 1 ? '' : 's') + '</summary>';
            for (var k = i; k < j; k++) html += '<span class="d-eq">  ' + escHtml(ops[k].l) + '</span>';
            html += '</details>';
            i = j;
        }
    }
    el.innerHTML = html;
}
</script>"#;



fn render_editing(live_text: &str, fetch_error: Option<&str>, sidebar: &SidebarData, mode: EditMode, saved_path: &str) -> String {
    let error_html = fetch_error
        .map(|e| format!("<div class='msg error'>{}</div>", he(e)))
        .unwrap_or_default();
    let live_js = js_str(live_text);
    let script = editing_script(&live_js, mode == EditMode::Saved, mode == EditMode::Running);
    let sidebar_html = render_sidebar(sidebar, mode == EditMode::Running);

    let (run_cls, sav_cls) = if mode == EditMode::Running {
        ("tab-btn active", "tab-btn")
    } else {
        ("tab-btn", "tab-btn active")
    };

    let heading = match mode {
        EditMode::Running => "Edit Ruleset — Running config".to_string(),
        EditMode::Saved => format!("Edit Ruleset — Saved config ({})", he(saved_path)),
    };

    let mode_controls = match mode {
        EditMode::Running => r#"<div><label for="mode-sel">Stage mode: <select id="mode-sel" name="mode">
    <option value="full">Full replacement</option>
    <option value="patch">Patch (incremental)</option>
  </select></label></div>"#,
        EditMode::Saved => r#"<input type="hidden" name="mode" value="saved_incremental">
  <p class="mode-hint">Staging applies only the tables in this file incrementally — other tables are left untouched.</p>"#,
    };

    let save_form = if mode == EditMode::Saved {
        r#"<form id="save-form" method="post" action="/save-config" class="save-inline">
  <input type="hidden" id="save-content" name="content">
  <button type="submit" class="btn-neutral">Save to disk</button>
</form>"#
    } else {
        ""
    };

    // log-container lives inside log-panel-slot in the HTML (correct grid position).
    // JS moves it into monitor-view when the Monitor tab is activated.
    let (layout_cls, log_panel) = if mode == EditMode::Running {
        (
            "editor-layout editor-layout-bp",
            r#"<div class="log-panel" id="log-panel-slot">
<h4>Log Output</h4>
<button type="button" class="btn-neutral btn-sm" id="go-monitor-btn"
  style="margin-bottom:.4em" title="Full view">⛶ Full view</button>
<div id="log-container">
<div class="log-controls">
  <button id="log-toggle" type="button" class="btn-neutral btn-sm">Monitor: off</button>
  <button id="log-clear" type="button" class="btn-neutral btn-sm">Clear</button>
  <label>Lines: <input id="log-max-input" type="number" value="50" min="10" max="9999"></label>
</div>
<div id="log-output"></div>
</div>
</div>"#,
        )
    } else {
        ("editor-layout", "")
    };

    // Monitor tab and view are always rendered so the tab is reachable from any mode.
    let mon_cls = "tab-btn"; // never "active" since it's a view toggle, not a URL mode
    format!(
        r#"<div class="mode-tabs">
  <a href="/" class="{run_cls}">Running config</a>
  <a href="/?mode=saved" class="{sav_cls}">Saved config</a>
  <button id="monitor-tab-btn" class="{mon_cls}" type="button">Monitor</button>
</div>
<div id="monitor-view" style="display:none">
<h2>Monitor</h2>
</div>
<div id="editor-view" class="{layout_cls}">
{log_panel}
<div>
{error_html}<h2>{heading}</h2>
<form method="post" action="/stage" id="stage-form">
  {mode_controls}
  <input type="hidden" id="content-hidden" name="content">
  <div id="editor"></div>
  <div class="form-btns">
    <button type="button" class="btn-neutral" id="validate-btn">Validate syntax</button>
    <button type="submit">Stage change</button>
  </div>
  <div id="validate-result"></div>
</form>
{save_form}
</div>
{sidebar_html}
</div>
{script}"#
    )
}

fn render_sidebar(sidebar: &SidebarData, with_log_groups: bool) -> String {
    let mut h = String::from("<aside class=\"sidebar\">\n");

    h.push_str("<h4>Interfaces</h4><ul>\n");
    if sidebar.interfaces.is_empty() {
        h.push_str("<li class=\"sb-empty\">None found</li>\n");
    } else {
        for iface in &sidebar.interfaces {
            h.push_str(&format!(
                "<li><button type=\"button\" class=\"sb-item\" onclick=\"window.fwInsert({ins})\">{name}</button></li>\n",
                ins = js_str(&format!("\"{iface}\"")),
                name = he(iface),
            ));
        }
    }
    h.push_str("</ul>\n");

    h.push_str("<h4>Defines</h4><ul>\n");
    if sidebar.defines.is_empty() {
        h.push_str("<li class=\"sb-empty\">None</li>\n");
    } else {
        for (name, val) in &sidebar.defines {
            h.push_str(&format!(
                "<li><button type=\"button\" class=\"sb-item\" onclick=\"window.fwInsert({ins})\" title=\"{val}\">${name}</button></li>\n",
                ins = js_str(&format!("${name}")),
                val = he(val),
                name = he(name),
            ));
        }
    }
    h.push_str("</ul>\n");

    h.push_str("<h4>Sets</h4><ul>\n");
    if sidebar.sets.is_empty() {
        h.push_str("<li class=\"sb-empty\">None</li>\n");
    } else {
        for set_name in &sidebar.sets {
            let insert = format!("@{set_name}");
            h.push_str(&format!(
                "<li><button type=\"button\" class=\"sb-item\" onclick=\"window.fwInsert({ins})\">{name}</button></li>\n",
                ins = js_str(&insert),
                name = he(&insert),
            ));
        }
    }
    h.push_str("</ul>\n");

    h.push_str("<h4>Help</h4>\n<ul class=\"sb-help\">\n");
    h.push_str("  <li><a href=\"https://wiki.nftables.org/\" target=\"_blank\" rel=\"noopener noreferrer\">nftables wiki \u{2197}</a></li>\n");
    h.push_str("  <li><button type=\"button\" class=\"btn-neutral btn-sm\" id=\"help-toggle\">Keyword help: off</button></li>\n");
    h.push_str("</ul>\n");

    if with_log_groups {
        h.push_str("<h4>Log Groups</h4>\n");
        h.push_str("<div id=\"bp-list\"><span class=\"sb-empty\">No breakpoints</span></div>\n");
        h.push_str("<p class=\"hint\">Click gutter to toggle</p>\n");
    }

    h.push_str("</aside>\n");
    h
}

fn render_staged(change: &StagedChange, live_text: &str) -> String {
    let live_esc = he(live_text);
    let content_esc = he(&change.content);
    let mode = he(&change.mode.to_string());
    let live_js = js_str(live_text);
    let staged_js = js_str(&change.content);

    let script = simple_diff_script(&live_js, &staged_js);

    format!(
        r#"<details>
  <summary>Live ruleset (current)</summary>
  <pre>{live_esc}</pre>
</details>
<h2>Staged Change — {mode}</h2>
<div class="msg warn">Review the diff carefully before promoting.</div>
<h3>Diff (live → staged)</h3>
<div class="diff-view" id="diff-view"></div>
<details class="staged-full">
  <summary>Full staged content</summary>
  <pre>{content_esc}</pre>
</details>
<div class="actions">
  <form method="post" action="/promote">
    <button type="submit" class="btn-danger">Promote to live</button>
  </form>
  <form method="post" action="/clear">
    <button type="submit">Clear</button>
  </form>
</div>
{script}"#
    )
}

fn render_promoting(change: &StagedChange, previous_text: &str, remaining: Duration) -> String {
    let mode = he(&change.mode.to_string());
    let secs = remaining.as_secs();
    let prev_js = js_str(previous_text);
    let promoted_js = js_str(&change.content);

    let script = promoting_script(&prev_js, &promoted_js, secs);

    format!(
        r#"<div class="msg warn">
  <strong>Change promoted — auto-rollback in <span id="countdown">{secs}</span>s.</strong>
  Acknowledge before the timer expires to keep this change.
</div>
<h2>Promoted Change — {mode}</h2>
<h3>Diff (previous → promoted)</h3>
<div class="diff-view" id="diff-view"></div>
<div class="actions">
  <form method="post" action="/acknowledge">
    <button type="submit" class="btn-safe">Acknowledge (keep change)</button>
  </form>
</div>
{script}"#
    )
}

// ---------------------------------------------------------------------------
// Script builders — concatenation avoids format! brace-escaping for JS code.
// ---------------------------------------------------------------------------

fn editing_script(live_js: &str, has_save_form: bool, is_running: bool) -> String {
    // type="module" so imports work; modules are deferred — DIFF_JS (in <head>) runs first.
    let mut s = String::from("<script type=\"module\">\n");
    s.push_str("import { basicSetup, EditorView, Decoration, WidgetType, hoverTooltip, keymap, indentWithTab, EditorState, StateEffect, StateField, Compartment, RangeSet, foldService, vim, gutter, GutterMarker, nftLanguage } from '/static/cm-bundle.js';\n");
    s.push_str("(function() {\n");
    s.push_str("  var original = "); s.push_str(live_js); s.push_str(";\n");
    s.push_str("  var valBtn = document.getElementById('validate-btn');\n");
    s.push_str("  var valOut = document.getElementById('validate-result');\n");

    // Widget for deleted-line markers (thin red bar shown between lines).
    s.push_str("  class DiffDelWidget extends WidgetType {\n");
    s.push_str("    toDOM() { var d = document.createElement('div'); d.className = 'cm-diff-del'; return d; }\n");
    s.push_str("    eq(other) { return other instanceof DiffDelWidget; }\n");
    s.push_str("    get estimatedHeight() { return 3; }\n");
    s.push_str("  }\n");

    // StateField for inline diff decorations (added lines + deletion markers).
    s.push_str("  var diffEffect = StateEffect.define();\n");
    s.push_str("  var diffField = StateField.define({\n");
    s.push_str("    create: function() { return Decoration.none; },\n");
    s.push_str("    update: function(deco, tr) {\n");
    s.push_str("      deco = deco.map(tr.changes);\n");
    s.push_str("      for (var i = 0; i < tr.effects.length; i++) {\n");
    s.push_str("        if (tr.effects[i].is(diffEffect)) deco = tr.effects[i].value;\n");
    s.push_str("      }\n");
    s.push_str("      return deco;\n");
    s.push_str("    },\n");
    s.push_str("    provide: function(f) { return EditorView.decorations.from(f); }\n");
    s.push_str("  });\n");

    // StateField for error-line decorations.
    s.push_str("  var errEffect = StateEffect.define();\n");
    s.push_str("  var errField = StateField.define({\n");
    s.push_str("    create: function() { return Decoration.none; },\n");
    s.push_str("    update: function(deco, tr) {\n");
    s.push_str("      deco = deco.map(tr.changes);\n");
    s.push_str("      for (var i = 0; i < tr.effects.length; i++) {\n");
    s.push_str("        if (tr.effects[i].is(errEffect)) deco = tr.effects[i].value;\n");
    s.push_str("      }\n");
    s.push_str("      return deco;\n");
    s.push_str("    },\n");
    s.push_str("    provide: function(f) { return EditorView.decorations.from(f); }\n");
    s.push_str("  });\n");

    // Compute and apply inline diff decorations against the live original.
    s.push_str("  function updateInlineDiff(v) {\n");
    s.push_str("    var ops = window.computeDiff(original, v.state.doc.toString());\n");
    s.push_str("    var decos = [], docLine = 1;\n");
    s.push_str("    for (var i = 0; i < ops.length; i++) {\n");
    s.push_str("      var op = ops[i];\n");
    s.push_str("      if (op.t === '=') {\n");
    s.push_str("        docLine++;\n");
    s.push_str("      } else if (op.t === '+') {\n");
    s.push_str("        if (docLine <= v.state.doc.lines) {\n");
    s.push_str("          var ln = v.state.doc.line(docLine);\n");
    s.push_str("          decos.push(Decoration.line({ class: 'cm-diff-add' }).range(ln.from));\n");
    s.push_str("        }\n");
    s.push_str("        docLine++;\n");
    s.push_str("      } else {\n"); // '-': deleted from original, show red bar before docLine
    s.push_str("        var pos = docLine <= v.state.doc.lines ? v.state.doc.line(docLine).from : v.state.doc.length;\n");
    s.push_str("        decos.push(Decoration.widget({ widget: new DiffDelWidget(), block: true, side: -1 }).range(pos));\n");
    s.push_str("      }\n");
    s.push_str("    }\n");
    s.push_str("    v.dispatch({ effects: diffEffect.of(Decoration.set(decos, true)) });\n");
    s.push_str("  }\n");

    // Restore draft if returning after a failed stage POST.
    s.push_str("  var initialContent = original;\n");
    s.push_str("  if (window.location.search.indexOf('error=') !== -1) {\n");
    s.push_str("    var draft = sessionStorage.getItem('fwgui_draft');\n");
    s.push_str("    if (draft !== null) { sessionStorage.removeItem('fwgui_draft'); initialContent = draft; }\n");
    s.push_str("  }\n");

    // nftables keyword help dictionary + hoverTooltip.
    s.push_str("  var NFT_HELP = {\n");
    s.push_str("    'table':    'Container for chains/sets/maps. Families: ip ip6 inet arp bridge netdev.',\n");
    s.push_str("    'chain':    'Ordered rules list. Base chains need hook, priority and policy; regular chains are jump targets.',\n");
    s.push_str("    'rule':     'A single match-and-action statement inside a chain.',\n");
    s.push_str("    'set':      'Named collection of addresses, ports, or other values for efficient matching.',\n");
    s.push_str("    'map':      'Named key→value store for lookups inside rules.',\n");
    s.push_str("    'hook':     'Netfilter attachment: prerouting input forward output postrouting ingress egress.',\n");
    s.push_str("    'policy':   'Default chain verdict when no rule matches: accept or drop.',\n");
    s.push_str("    'priority': 'Controls processing order when multiple chains share a hook. Lower runs first.',\n");
    s.push_str("    'type':     'Chain type: filter nat route. Or set/map element type.',\n");
    s.push_str("    'accept':   'Verdict: allow the packet to continue through the stack.',\n");
    s.push_str("    'drop':     'Verdict: silently discard the packet.',\n");
    s.push_str("    'reject':   'Verdict: discard and send an error reply (ICMP unreachable or TCP RST).',\n");
    s.push_str("    'return':   'Verdict: stop processing this chain and return to the calling chain.',\n");
    s.push_str("    'jump':     'Verdict: process the named chain then return here.',\n");
    s.push_str("    'goto':     'Verdict: process the named chain without returning.',\n");
    s.push_str("    'iifname':  'Match on incoming interface name (string). Slower than iif but handles dynamic interfaces.',\n");
    s.push_str("    'oifname':  'Match on outgoing interface name (string). Slower than oif but handles dynamic interfaces.',\n");
    s.push_str("    'iif':      'Match on incoming interface index (integer). Faster than iifname.',\n");
    s.push_str("    'oif':      'Match on outgoing interface index (integer). Faster than oifname.',\n");
    s.push_str("    'saddr':    'Match on source IP address or prefix.',\n");
    s.push_str("    'daddr':    'Match on destination IP address or prefix.',\n");
    s.push_str("    'sport':    'Match on source port number or range.',\n");
    s.push_str("    'dport':    'Match on destination port number or range.',\n");
    s.push_str("    'ct':       'Connection tracking. ct state: new established related invalid untracked.',\n");
    s.push_str("    'state':    'ct state values: new established related invalid untracked.',\n");
    s.push_str("    'ip':       'IPv4 header fields, or the ip table family.',\n");
    s.push_str("    'ip6':      'IPv6 header fields, or the ip6 table family.',\n");
    s.push_str("    'inet':     'Dual-stack family covering both IPv4 and IPv6 in one table.',\n");
    s.push_str("    'tcp':      'TCP protocol fields: flags dport sport sequence ack-seq window.',\n");
    s.push_str("    'udp':      'UDP protocol fields: sport dport length checksum.',\n");
    s.push_str("    'icmp':     'ICMPv4 fields: type code id sequence.',\n");
    s.push_str("    'icmpv6':   'ICMPv6 fields: type code.',\n");
    s.push_str("    'counter':  'Counts matching packets and bytes. Attach to any rule.',\n");
    s.push_str("    'log':      'Log matching packets to the kernel log (dmesg/journald). Options: prefix level group.',\n");
    s.push_str("    'limit':    'Rate-limit: limit rate N/second burst M packets.',\n");
    s.push_str("    'masquerade': 'NAT: rewrite source address to the outgoing interface address (for dynamic IPs).',\n");
    s.push_str("    'snat':     'Source NAT: rewrite source to a fixed address. to <addr>.',\n");
    s.push_str("    'dnat':     'Destination NAT: redirect to a fixed address. to <addr>[:<port>].',\n");
    s.push_str("    'define':   'Assign a symbolic name to a value: define NAME = value. Reference as $NAME.',\n");
    s.push_str("    'flush':    'Remove all rules/elements: flush ruleset|table|chain|set <name>.',\n");
    s.push_str("    'delete':   'Remove a specific named object from the ruleset.',\n");
    s.push_str("    'add':      'Add a table, chain, rule, or set element.',\n");
    s.push_str("    'insert':   'Insert a rule at the front of a chain.',\n");
    s.push_str("    'replace':  'Replace an existing rule identified by handle number.',\n");
    s.push_str("  };\n");
    s.push_str("  function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }\n");
    s.push_str("  var kwHelp = hoverTooltip(function(view, pos) {\n");
    s.push_str("    var line = view.state.doc.lineAt(pos);\n");
    s.push_str("    var text = line.text, off = pos - line.from;\n");
    s.push_str("    var start = off, end = off;\n");
    s.push_str("    while (start > 0 && /\\w/.test(text[start - 1])) start--;\n");
    s.push_str("    while (end < text.length && /\\w/.test(text[end])) end++;\n");
    s.push_str("    if (start === end) return null;\n");
    s.push_str("    var word = text.slice(start, end);\n");
    s.push_str("    var tip = NFT_HELP[word];\n");
    s.push_str("    if (!tip) return null;\n");
    s.push_str("    return { pos: line.from + start, end: line.from + end, above: true, create: function() {\n");
    s.push_str("      var d = document.createElement('div');\n");
    s.push_str("      d.className = 'nft-tooltip';\n");
    s.push_str("      d.innerHTML = '<strong>' + esc(word) + '</strong>: ' + esc(tip);\n");
    s.push_str("      return { dom: d };\n");
    s.push_str("    }};\n");
    s.push_str("  });\n");
    s.push_str("  var helpComp = new Compartment();\n");

    // Brace-based fold service for nftables { } blocks.
    s.push_str("  var nftFold = foldService.of(function(state, lineFrom, lineTo) {\n");
    s.push_str("    var lineText = state.sliceDoc(lineFrom, lineTo);\n");
    s.push_str("    var openIdx = lineText.lastIndexOf('{');\n");
    s.push_str("    if (openIdx < 0) return null;\n");
    s.push_str("    var openPos = lineFrom + openIdx;\n");
    s.push_str("    var depth = 1, cur = openPos + 1;\n");
    s.push_str("    while (cur < state.doc.length && depth > 0) {\n");
    s.push_str("      var ch = state.sliceDoc(cur, cur + 1);\n");
    s.push_str("      if (ch === '{') depth++;\n");
    s.push_str("      else if (ch === '}') { depth--; if (depth === 0) break; }\n");
    s.push_str("      cur++;\n");
    s.push_str("    }\n");
    s.push_str("    if (depth !== 0) return null;\n");
    s.push_str("    var closeLine = state.doc.lineAt(cur);\n");
    s.push_str("    return { from: openPos + 1, to: closeLine.from - 1 };\n");
    s.push_str("  });\n");

    // Breakpoint gutter (running config mode only).
    // Follows the official CM6 pattern: StateField<RangeSet<GutterMarker>> + gutter({markers}).
    let bp_gutter_ext = if is_running { "bpGutter," } else { "" };
    if is_running {
        // Two effects: toggle a single position, or replace the whole set from server sync.
        s.push_str("  var bpToggle = StateEffect.define({ map: function(v,m){ return {pos:m.mapPos(v.pos),on:v.on}; } });\n");
        s.push_str("  var bpReset = StateEffect.define();\n");

        // StateField stores a RangeSet<GutterMarker>.
        s.push_str("  class BpMarker extends GutterMarker {\n");
        s.push_str("    toDOM() { var d=document.createElement('div'); d.className='bp-marker'; d.textContent='\\u25CF'; return d; }\n");
        s.push_str("  }\n");
        s.push_str("  var bpMarker = new BpMarker();\n");

        s.push_str("  var bpField = StateField.define({\n");
        s.push_str("    create: function() { return RangeSet.empty; },\n");
        s.push_str("    update: function(set, tr) {\n");
        s.push_str("      set = set.map(tr.changes);\n");
        s.push_str("      for (var i=0; i<tr.effects.length; i++) {\n");
        s.push_str("        var e = tr.effects[i];\n");
        s.push_str("        if (e.is(bpReset)) return e.value;\n");
        s.push_str("        if (e.is(bpToggle)) {\n");
        s.push_str("          if (e.value.on) set = set.update({add:[bpMarker.range(e.value.pos)]});\n");
        s.push_str("          else { var rm=e.value.pos; set = set.update({filter:function(f){return f!==rm;}}); }\n");
        s.push_str("        }\n");
        s.push_str("      }\n");
        s.push_str("      return set;\n");
        s.push_str("    }\n");
        s.push_str("  });\n");

        s.push_str("  var bpGutter = gutter({\n");
        s.push_str("    class: 'cm-bp-gutter',\n");
        s.push_str("    markers: function(v) { return v.state.field(bpField); },\n");
        s.push_str("    initialSpacer: function() { return bpMarker; },\n");
        s.push_str("    domEventHandlers: {\n");
        s.push_str("      mousedown: function(view, line) {\n");
        s.push_str("        var pos = line.from;\n");
        s.push_str("        var lineNo = view.state.doc.lineAt(pos).number;\n");
        s.push_str("        var has = false;\n");
        s.push_str("        view.state.field(bpField).between(pos, pos, function(){ has=true; });\n");
        s.push_str("        if (has) {\n");
        s.push_str("          clearBreakpoint(view, pos, lineNo-1);\n");
        s.push_str("        } else {\n");
        s.push_str("          setBreakpoint(view, pos, lineNo-1);\n");
        s.push_str("        }\n");
        s.push_str("        return true;\n");
        s.push_str("      }\n");
        s.push_str("    }\n");
        s.push_str("  });\n");
    }

    // Create the CodeMirror editor.
    s.push_str("  var view = new EditorView({\n");
    s.push_str("    state: EditorState.create({\n");
    s.push_str("      doc: initialContent,\n");
    s.push_str("      extensions: [\n");
    s.push_str("        vim(),\n");
    s.push_str(&format!("        {bp_gutter_ext}\n"));
    s.push_str("        basicSetup,\n");
    s.push_str("        nftLanguage.extension,\n");
    s.push_str("        nftFold,\n");
    s.push_str("        helpComp.of([]),\n");
    s.push_str("        keymap.of([indentWithTab]),\n");
    s.push_str("        diffField,\n");
    s.push_str("        errField,\n");
    if is_running {
        // bpField must be explicit so view.state.field(bpField) works inside gutter markers/handlers.
        s.push_str("        bpField,\n");
    }
    s.push_str("        EditorView.updateListener.of(function(update) {\n");
    s.push_str("          if (update.docChanged) updateInlineDiff(update.view);\n");
    s.push_str("        }),\n");
    s.push_str("      ]\n");
    s.push_str("    }),\n");
    s.push_str("    parent: document.getElementById('editor')\n");
    s.push_str("  });\n");

    // Apply initial diff decorations.
    s.push_str("  updateInlineDiff(view);\n");

    // Breakpoint and log stream helpers (running config mode only).
    if is_running {
        // DOM refs.
        s.push_str("  var logEl = document.getElementById('log-output');\n");
        s.push_str("  var logToggle = document.getElementById('log-toggle');\n");
        s.push_str("  var logClear = document.getElementById('log-clear');\n");
        s.push_str("  var logMaxInput = document.getElementById('log-max-input');\n");
        s.push_str("  var logContainer = document.getElementById('log-container');\n");
        s.push_str("  var logPanelSlot = document.getElementById('log-panel-slot');\n");
        s.push_str("  var editorView = document.getElementById('editor-view');\n");
        s.push_str("  var monitorView = document.getElementById('monitor-view');\n");
        s.push_str("  var monitorTabBtn = document.getElementById('monitor-tab-btn');\n");
        s.push_str("  var goMonitorBtn = document.getElementById('go-monitor-btn');\n");
        // log-container is already inside log-panel-slot in the HTML — no move needed on load.

        s.push_str("  function showBpError(msg) {\n");
        s.push_str("    var d = document.createElement('div'); d.className = 'log-line'; d.style.color = '#f88';\n");
        s.push_str("    d.textContent = 'Breakpoint error: ' + msg;\n");
        s.push_str("    logEl.appendChild(d); logEl.scrollTop = logEl.scrollHeight;\n");
        s.push_str("  }\n");

        // Monitor tab switching — moves log-container without reloading the page,
        // so the SSE connection and log entries are preserved.
        s.push_str("  var monitorTabActive = false;\n");
        s.push_str("  function activateMonitorTab() {\n");
        s.push_str("    monitorTabActive = true;\n");
        s.push_str("    editorView.style.display = 'none';\n");
        s.push_str("    monitorView.appendChild(logContainer);\n");
        s.push_str("    monitorView.style.display = '';\n");
        s.push_str("    monitorTabBtn.classList.add('active');\n");
        s.push_str("  }\n");
        s.push_str("  function activateEditorTab() {\n");
        s.push_str("    monitorTabActive = false;\n");
        s.push_str("    monitorView.style.display = 'none';\n");
        s.push_str("    logPanelSlot.appendChild(logContainer);\n");
        s.push_str("    editorView.style.display = '';\n");
        s.push_str("    monitorTabBtn.classList.remove('active');\n");
        s.push_str("  }\n");
        s.push_str("  monitorTabBtn.addEventListener('click', function() {\n");
        s.push_str("    if (monitorTabActive) activateEditorTab(); else activateMonitorTab();\n");
        s.push_str("  });\n");
        s.push_str("  goMonitorBtn.addEventListener('click', activateMonitorTab);\n");

        s.push_str("  function updateBpSidebar(list) {\n");
        s.push_str("    var el = document.getElementById('bp-list');\n");
        s.push_str("    if (!list.length) { el.innerHTML = '<span class=\"sb-empty\">No breakpoints</span>'; return; }\n");
        s.push_str("    var html = '<ul style=\"margin:.2em 0;padding:0 0 0 .5em\">';\n");
        s.push_str("    for (var i=0; i<list.length; i++) {\n");
        s.push_str("      var bp = list[i];\n");
        s.push_str("      html += '<li style=\"padding:.1em 0\"><button type=\"button\" class=\"sb-item\" style=\"color:#c00\" data-line=\"'+bp.line+'\">\\u25CF</button> L'+(bp.line+1)+' '+bp.chain_name+'</li>';\n");
        s.push_str("    }\n");
        s.push_str("    html += '</ul>';\n");
        s.push_str("    el.innerHTML = html;\n");
        s.push_str("    var btns = el.querySelectorAll('.sb-item[data-line]');\n");
        s.push_str("    for (var j=0; j<btns.length; j++) {\n");
        s.push_str("      btns[j].addEventListener('click', (function(btn){\n");
        s.push_str("        return function() {\n");
        s.push_str("          var zl = parseInt(btn.dataset.line);\n");
        s.push_str("          var pos = (zl+1 <= view.state.doc.lines) ? view.state.doc.line(zl+1).from : 0;\n");
        s.push_str("          clearBreakpoint(view, pos, zl);\n");
        s.push_str("        };\n");
        s.push_str("      })(btns[j]));\n");
        s.push_str("    }\n");
        s.push_str("  }\n");

        // SSE monitor start/stop — persist state in localStorage.
        s.push_str("  var evtSource = null;\n");
        s.push_str("  function startMonitor() {\n");
        s.push_str("    if (evtSource) return;\n");
        s.push_str("    evtSource = new EventSource('/log-stream');\n");
        s.push_str("    evtSource.onmessage = function(e) {\n");
        s.push_str("      var d = document.createElement('div'); d.className = 'log-line'; d.textContent = e.data;\n");
        s.push_str("      logEl.appendChild(d);\n");
        s.push_str("      var cap = Math.max(10, parseInt(logMaxInput.value) || 50);\n");
        s.push_str("      while (logEl.childElementCount > cap) logEl.removeChild(logEl.firstChild);\n");
        s.push_str("      logEl.scrollTop = logEl.scrollHeight;\n");
        s.push_str("    };\n");
        s.push_str("    evtSource.onerror = function() {\n");
        s.push_str("      logToggle.textContent = 'Monitor: off'; evtSource.close(); evtSource = null;\n");
        s.push_str("    };\n");
        s.push_str("    logToggle.textContent = 'Monitor: on';\n");
        s.push_str("    localStorage.setItem('fwgui-monitor', '1');\n");
        s.push_str("  }\n");
        s.push_str("  function stopMonitor() {\n");
        s.push_str("    if (!evtSource) return;\n");
        s.push_str("    evtSource.close(); evtSource = null; logToggle.textContent = 'Monitor: off';\n");
        s.push_str("    localStorage.removeItem('fwgui-monitor');\n");
        s.push_str("  }\n");
        s.push_str("  logToggle.addEventListener('click', function() { if (evtSource) stopMonitor(); else startMonitor(); });\n");
        s.push_str("  logClear.addEventListener('click', function() { logEl.innerHTML = ''; });\n");

        // Sync gutter + sidebar from server list.
        // Does NOT auto-start here — localStorage check on page load handles that.
        s.push_str("  function syncBreakpoints() {\n");
        s.push_str("    fetch('/breakpoints').then(function(r){return r.json();}).then(function(list){\n");
        s.push_str("      var ranges = [];\n");
        s.push_str("      for (var i=0; i<list.length; i++) {\n");
        s.push_str("        var lineNo = list[i].line + 1;\n");
        s.push_str("        if (lineNo <= view.state.doc.lines) ranges.push(bpMarker.range(view.state.doc.line(lineNo).from));\n");
        s.push_str("      }\n");
        s.push_str("      ranges.sort(function(a,b){return a.from-b.from;});\n");
        s.push_str("      view.dispatch({ effects: bpReset.of(RangeSet.of(ranges, true)) });\n");
        s.push_str("      updateBpSidebar(list);\n");
        s.push_str("    }).catch(function(){});\n");
        s.push_str("  }\n");

        // pos = doc position; zeroLine = 0-based line for server.
        // Auto-start monitor on first breakpoint (when no others exist).
        s.push_str("  function setBreakpoint(v, pos, zeroLine) {\n");
        s.push_str("    var isFirst = (v.state.field(bpField).size === 0);\n");
        s.push_str("    fetch('/breakpoint', {\n");
        s.push_str("      method: 'POST', headers: {'Content-Type':'application/json'},\n");
        s.push_str("      body: JSON.stringify({line: zeroLine})\n");
        s.push_str("    }).then(function(r){return r.json();}).then(function(data){\n");
        s.push_str("      if (data.ok) {\n");
        s.push_str("        v.dispatch({ effects: bpToggle.of({pos:pos, on:true}) });\n");
        s.push_str("        if (isFirst && !evtSource) startMonitor();\n");
        s.push_str("        syncBreakpoints();\n");
        s.push_str("      } else { showBpError(data.error || 'unknown'); }\n");
        s.push_str("    }).catch(function(e){ showBpError(String(e)); });\n");
        s.push_str("  }\n");

        s.push_str("  function clearBreakpoint(v, pos, zeroLine) {\n");
        s.push_str("    fetch('/breakpoint/'+zeroLine, {method:'DELETE'})\n");
        s.push_str("      .then(function(r){return r.json();})\n");
        s.push_str("      .then(function(data){\n");
        s.push_str("        if (data.ok) {\n");
        s.push_str("          v.dispatch({ effects: bpToggle.of({pos:pos, on:false}) });\n");
        s.push_str("          syncBreakpoints();\n");
        s.push_str("        } else { showBpError(data.error || 'unknown'); }\n");
        s.push_str("      }).catch(function(){});\n");
        s.push_str("  }\n");

        // Page load: restore monitor from localStorage, then sync breakpoints.
        s.push_str("  if (localStorage.getItem('fwgui-monitor')) startMonitor();\n");
        s.push_str("  syncBreakpoints();\n");
    } else {
        // Non-running modes: Monitor tab navigates to running config.
        s.push_str("  var _mb = document.getElementById('monitor-tab-btn');\n");
        s.push_str("  if (_mb) _mb.onclick = function() { window.location.href = '/'; };\n");
    }

    // Expose insert helper for sidebar click handlers.
    s.push_str("  window.fwInsert = function(text) {\n");
    s.push_str("    view.dispatch(view.state.replaceSelection(text));\n");
    s.push_str("    view.focus();\n");
    s.push_str("  };\n");

    // Keyword help toggle.
    s.push_str("  var helpBtn = document.getElementById('help-toggle');\n");
    s.push_str("  if (helpBtn) {\n");
    s.push_str("    var helpOn = false;\n");
    s.push_str("    helpBtn.addEventListener('click', function() {\n");
    s.push_str("      helpOn = !helpOn;\n");
    s.push_str("      helpBtn.textContent = 'Keyword help: ' + (helpOn ? 'on' : 'off');\n");
    s.push_str("      view.dispatch({ effects: helpComp.reconfigure(helpOn ? [kwHelp] : []) });\n");
    s.push_str("    });\n");
    s.push_str("  }\n");

    // Parse nft caret-format error output → 0-indexed line numbers.
    s.push_str("  function getErrorLines(errText, docText) {\n");
    s.push_str("    var el = errText.split('\\n'), dl = docText.split('\\n'), out = [];\n");
    s.push_str("    for (var i = 0; i < el.length - 1; i++) {\n");
    s.push_str("      if (/^\\s*\\^\\s*$/.test(el[i + 1])) {\n");
    s.push_str("        var src = el[i];\n");
    s.push_str("        for (var j = 0; j < dl.length; j++) {\n");
    s.push_str("          if ((dl[j] === src || dl[j].trim() === src.trim()) && out.indexOf(j) === -1)\n");
    s.push_str("            out.push(j);\n");
    s.push_str("        }\n");
    s.push_str("      }\n");
    s.push_str("    }\n");
    s.push_str("    return out;\n");
    s.push_str("  }\n");

    // Apply or clear error-line decorations (0-indexed line numbers).
    s.push_str("  function setErrorLines(lineNums) {\n");
    s.push_str("    if (!lineNums.length) {\n");
    s.push_str("      view.dispatch({ effects: errEffect.of(Decoration.none) });\n");
    s.push_str("      return;\n");
    s.push_str("    }\n");
    s.push_str("    var decos = lineNums\n");
    s.push_str("      .filter(function(n) { return n + 1 <= view.state.doc.lines; })\n");
    s.push_str("      .map(function(n) {\n");
    s.push_str("        var line = view.state.doc.line(n + 1);\n");
    s.push_str("        return Decoration.line({ class: 'cm-err-line' }).range(line.from);\n");
    s.push_str("      })\n");
    s.push_str("      .sort(function(a, b) { return a.from - b.from; });\n");
    s.push_str("    view.dispatch({ effects: errEffect.of(Decoration.set(decos, true)) });\n");
    s.push_str("  }\n");

    // Copy editor content to hidden input and save draft before form submit.
    s.push_str("  document.getElementById('stage-form').addEventListener('submit', function() {\n");
    s.push_str("    var content = view.state.doc.toString();\n");
    s.push_str("    sessionStorage.setItem('fwgui_draft', content);\n");
    s.push_str("    document.getElementById('content-hidden').value = content;\n");
    s.push_str("  });\n");

    if has_save_form {
        s.push_str("  document.getElementById('save-form').addEventListener('submit', function() {\n");
        s.push_str("    document.getElementById('save-content').value = view.state.doc.toString();\n");
        s.push_str("  });\n");
    }

    // Validate button.
    s.push_str("  valBtn.addEventListener('click', function() {\n");
    s.push_str("    setErrorLines([]);\n");
    s.push_str("    valBtn.disabled = true;\n");
    s.push_str("    valBtn.textContent = 'Validating\u{2026}';\n");
    s.push_str("    var content = view.state.doc.toString();\n");
    s.push_str("    fetch('/validate', {\n");
    s.push_str("      method: 'POST',\n");
    s.push_str("      headers: {'Content-Type': 'application/x-www-form-urlencoded'},\n");
    s.push_str("      body: 'content=' + encodeURIComponent(content)\n");
    s.push_str("    }).then(function(r) { return r.json(); }).then(function(data) {\n");
    s.push_str("      if (data.ok) {\n");
    s.push_str("        valOut.className = 'msg notice';\n");
    s.push_str("        valOut.textContent = 'Syntax valid \u{2713}';\n");
    s.push_str("        setErrorLines([]);\n");
    s.push_str("      } else {\n");
    s.push_str("        var errText = data.error || 'unknown error';\n");
    s.push_str("        valOut.className = 'msg error';\n");
    s.push_str("        valOut.textContent = 'Invalid: ' + errText;\n");
    s.push_str("        setErrorLines(getErrorLines(errText, content));\n");
    s.push_str("      }\n");
    s.push_str("    }).catch(function(e) {\n");
    s.push_str("      valOut.className = 'msg error';\n");
    s.push_str("      valOut.textContent = 'Validation request failed: ' + e;\n");
    s.push_str("    }).finally(function() {\n");
    s.push_str("      valBtn.disabled = false;\n");
    s.push_str("      valBtn.textContent = 'Validate syntax';\n");
    s.push_str("    });\n");
    s.push_str("  });\n");
    s.push_str("})();\n</script>");
    s
}

fn simple_diff_script(a_js: &str, b_js: &str) -> String {
    let mut s = String::from("<script>\n(function() {\n");
    s.push_str("  var a = "); s.push_str(a_js); s.push_str(";\n");
    s.push_str("  var b = "); s.push_str(b_js); s.push_str(";\n");
    s.push_str("  renderDiff(computeDiff(a, b), document.getElementById('diff-view'));\n");
    s.push_str("})();\n</script>");
    s
}

fn promoting_script(prev_js: &str, promoted_js: &str, secs: u64) -> String {
    let mut s = String::from("<script>\n(function() {\n");
    s.push_str("  var prev = "); s.push_str(prev_js); s.push_str(";\n");
    s.push_str("  var promoted = "); s.push_str(promoted_js); s.push_str(";\n");
    s.push_str("  renderDiff(computeDiff(prev, promoted), document.getElementById('diff-view'));\n");
    s.push_str(&format!("  var n = {};\n", secs));
    s.push_str("  var el = document.getElementById('countdown');\n");
    s.push_str("  var timer = setInterval(function() {\n");
    s.push_str("    n -= 1;\n");
    s.push_str("    if (n <= 0) { clearInterval(timer); el.textContent = '0'; location.reload(); }\n");
    s.push_str("    else { el.textContent = n; }\n");
    s.push_str("  }, 1000);\n");
    s.push_str("})();\n</script>");
    s
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// HTML-escape user content before inserting into the page.
fn he(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// JSON-encode a string for safe embedding as a JavaScript string literal.
fn js_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

fn redirect_error(msg: &str) -> Redirect {
    Redirect::to(&format!("/?error={}", url_encode(msg)))
}

fn redirect_notice(msg: &str) -> Redirect {
    Redirect::to(&format!("/?notice={}", url_encode(msg)))
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

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
