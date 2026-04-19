use axum::{
    Json,
    extract::{Query, State},
    response::{Html, Redirect},
    Form,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

use crate::nft;
use crate::state::{AppState, ChangeMode, FwState, StagedChange};

#[derive(Deserialize)]
pub struct IndexQuery {
    error: Option<String>,
    notice: Option<String>,
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
    let (live_text, live_error) = match nft::get_ruleset_text() {
        Ok(t) => (t, None),
        Err(e) => (String::new(), Some(e.to_string())),
    };

    let fw = state.fw.lock().unwrap();
    let body = match &*fw {
        FwState::Idle => render_editing(&live_text, live_error.as_deref()),
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
    let mode = match form.mode.as_str() {
        "full" => ChangeMode::Full,
        "patch" => ChangeMode::Patch,
        _ => return redirect_error("Invalid mode"),
    };
    if let Err(e) = nft::validate_script(&form.content) {
        return redirect_error(&format!("Validation failed: {e}"));
    }
    let mut fw = state.fw.lock().unwrap();
    if matches!(*fw, FwState::Promoting { .. }) {
        return redirect_error("Cannot stage a change while promotion is pending");
    }
    *fw = FwState::Staged(StagedChange { mode, content: form.content });
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
    let cancel_tx = match std::mem::replace(&mut *fw, FwState::Idle) {
        FwState::Promoting { cancel_tx, .. } => cancel_tx,
        _ => unreachable!(),
    };
    drop(fw);
    let _ = cancel_tx.send(());
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
  body {{ font-family: monospace; max-width: 960px; margin: 2em auto; padding: 0 1em; background: #fafafa; }}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: .25em; }}
  h2 {{ border-bottom: 1px solid #aaa; padding-bottom: .15em; margin-top: 1.5em; }}
  h3 {{ margin-top: 1em; color: #444; }}
  pre {{ background: #f0f0f0; padding: 1em; overflow-x: auto; white-space: pre-wrap; border: 1px solid #ddd; margin: 0; }}
  select {{ margin-bottom: .5em; padding: .25em; }}
  button {{ padding: .4em .9em; margin: .2em; cursor: pointer; font-size: 1em; }}
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
  .d-sep  {{ color: #bbb; padding: 0 1em; display: block; user-select: none; }}
  #countdown {{ font-size: 1.6em; font-weight: bold; color: #b00; }}
  #validate-result {{ margin-top: .5em; min-height: 1.5em; }}
  .actions {{ margin-top: .75em; }}
  #editor {{ height: 320px; border: 1px solid #ccc; border-radius: 2px; font-size: .9em; }}
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
    var changed = ops.some(function(o) { return o.t !== '='; });
    if (ops.length === 0 || !changed) {
        el.innerHTML = '<span class="d-none">No changes.</span>';
        return;
    }
    el.innerHTML = ops.map(function(op) {
        var e = escHtml(op.l);
        if (op.t === '+') return '<span class="d-add">+ ' + e + '</span>';
        if (op.t === '-') return '<span class="d-del">- ' + e + '</span>';
        return '<span class="d-eq">  ' + e + '</span>';
    }).join('');
}

// Like renderDiff but omits unchanged lines, inserting a separator between
// distinct change groups so position in the file remains clear.
function renderDiffChanged(ops, el) {
    var changed = ops.some(function(o) { return o.t !== '='; });
    if (ops.length === 0 || !changed) {
        el.innerHTML = '<span class="d-none">No changes.</span>';
        return;
    }
    var html = '', inChange = false;
    for (var i = 0; i < ops.length; i++) {
        var op = ops[i];
        if (op.t === '=') {
            if (inChange) {
                // Only emit separator if more changes follow.
                var more = false;
                for (var j = i + 1; j < ops.length; j++) { if (ops[j].t !== '=') { more = true; break; } }
                if (more) html += '<span class="d-sep">\u00b7\u00b7\u00b7</span>';
            }
            inChange = false;
        } else {
            var e = escHtml(op.l);
            html += op.t === '+' ? '<span class="d-add">+ ' + e + '</span>'
                                 : '<span class="d-del">- ' + e + '</span>';
            inChange = true;
        }
    }
    el.innerHTML = html;
}
</script>"#;



fn render_editing(live_text: &str, fetch_error: Option<&str>) -> String {
    let error_html = fetch_error
        .map(|e| format!("<div class='msg error'>Could not load live ruleset: {}</div>", he(e)))
        .unwrap_or_default();
    let live_js = js_str(live_text);

    let script = editing_script(&live_js);

    format!(
        r#"{error_html}<h2>Edit Ruleset</h2>
<form method="post" action="/stage" id="stage-form">
  <label for="mode-sel">Mode:</label>
  <select id="mode-sel" name="mode">
    <option value="full">Full replacement</option>
    <option value="patch">Patch (incremental)</option>
  </select><br>
  <input type="hidden" id="content-hidden" name="content">
  <div id="editor"></div>
  <div style="margin:.5em 0">
    <button type="button" class="btn-neutral" id="validate-btn">Validate syntax</button>
    <button type="submit">Stage change</button>
  </div>
  <div id="validate-result"></div>
</form>
{script}"#
    )
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
<details style="margin-top:.75em">
  <summary>Full staged content</summary>
  <pre>{content_esc}</pre>
</details>
<div class="actions">
  <form method="post" action="/promote" style="display:inline">
    <button type="submit" class="btn-danger">Promote to live</button>
  </form>
  <form method="post" action="/clear" style="display:inline">
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

fn editing_script(live_js: &str) -> String {
    // type="module" so imports work; modules are deferred — DIFF_JS (in <head>) runs first.
    let mut s = String::from("<script type=\"module\">\n");
    s.push_str("import { basicSetup, EditorView, Decoration, WidgetType, EditorState, StateEffect, StateField, vim } from '/static/cm-bundle.js';\n");
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

    // Create the CodeMirror editor.
    s.push_str("  var view = new EditorView({\n");
    s.push_str("    state: EditorState.create({\n");
    s.push_str("      doc: initialContent,\n");
    s.push_str("      extensions: [\n");
    s.push_str("        vim(),\n");
    s.push_str("        basicSetup,\n");
    s.push_str("        diffField,\n");
    s.push_str("        errField,\n");
    s.push_str("        EditorView.updateListener.of(function(update) {\n");
    s.push_str("          if (update.docChanged) updateInlineDiff(update.view);\n");
    s.push_str("        }),\n");
    s.push_str("      ]\n");
    s.push_str("    }),\n");
    s.push_str("    parent: document.getElementById('editor')\n");
    s.push_str("  });\n");

    // Apply initial diff decorations.
    s.push_str("  updateInlineDiff(view);\n");

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
    s.push_str("  renderDiffChanged(computeDiff(a, b), document.getElementById('diff-view'));\n");
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
