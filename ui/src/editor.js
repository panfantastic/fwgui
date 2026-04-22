import { basicSetup } from "codemirror";
import { EditorView, Decoration, WidgetType, hoverTooltip, keymap, gutter, GutterMarker } from "@codemirror/view";
import { EditorState, StateEffect, StateField, Compartment, RangeSet } from "@codemirror/state";
import { foldService } from "@codemirror/language";
import { indentWithTab } from "@codemirror/commands";
import { vim } from "@replit/codemirror-vim";
import { nftLanguage } from "./nft-language.js";

// ---- Diff utilities -------------------------------------------------------

function lcsTable(a, b) {
  var m = a.length, n = b.length;
  var c = [];
  for (var i = 0; i <= m; i++) c.push(new Array(n + 1).fill(0));
  for (var i = 1; i <= m; i++)
    for (var j = 1; j <= n; j++)
      c[i][j] = a[i-1] === b[j-1] ? c[i-1][j-1] + 1 : Math.max(c[i-1][j], c[i][j-1]);
  return c;
}

function normLine(l) { return l.replace(/\t/g, '    ').replace(/\s+$/, ''); }

function computeDiff(origText, editText) {
  var a = origText === '' ? [] : origText.split('\n').map(normLine);
  var b = editText  === '' ? [] : editText.split('\n').map(normLine);
  var c = lcsTable(a, b);
  var ops = [], i = a.length, j = b.length;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i-1] === b[j-1]) { ops.unshift({t:'=', l:a[i-1]}); i--; j--; }
    else if (j > 0 && (i === 0 || c[i][j-1] >= c[i-1][j])) { ops.unshift({t:'+', l:b[j-1]}); j--; }
    else { ops.unshift({t:'-', l:a[i-1]}); i--; }
  }
  return ops;
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function renderDiff(ops, el) {
  var CONTEXT = 3;
  if (ops.length === 0 || !ops.some(function(o) { return o.t !== '='; })) {
    el.innerHTML = '<span class="d-none">No changes.</span>';
    return;
  }
  var show = new Array(ops.length).fill(false);
  for (var i = 0; i < ops.length; i++) {
    if (ops[i].t !== '=') {
      var lo = Math.max(0, i - CONTEXT), hi = Math.min(ops.length - 1, i + CONTEXT);
      for (var k = lo; k <= hi; k++) show[k] = true;
    }
  }
  var html = '', idx = 0;
  while (idx < ops.length) {
    if (show[idx]) {
      var e = escHtml(ops[idx].l);
      if (ops[idx].t === '+') html += '<span class="d-add">+ ' + e + '</span>';
      else if (ops[idx].t === '-') html += '<span class="d-del">- ' + e + '</span>';
      else html += '<span class="d-eq">  ' + e + '</span>';
      idx++;
    } else {
      var j = idx;
      while (j < ops.length && !show[j]) j++;
      var n = j - idx;
      html += '<details class="d-fold"><summary>' + n + ' unchanged line' + (n === 1 ? '' : 's') + '</summary>';
      for (var k = idx; k < j; k++) html += '<span class="d-eq">  ' + escHtml(ops[k].l) + '</span>';
      html += '</details>';
      idx = j;
    }
  }
  el.innerHTML = html;
}

// ---- State management -----------------------------------------------------

const app = document.getElementById('app');
let countdownTimer = null;

async function loadAndRender() {
  const params = new URLSearchParams(location.search);
  try {
    const resp = await fetch('/api/state?' + params.toString());
    if (!resp.ok) throw new Error(await resp.text());
    render(await resp.json());
  } catch (e) {
    app.innerHTML = '<div class="msg error">Failed to load state: ' + escHtml(String(e)) + '</div>';
  }
}

function render(state) {
  if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
  if (state.phase === 'editing')   renderEditing(state);
  else if (state.phase === 'staged')   renderStaged(state);
  else if (state.phase === 'promoting') renderPromoting(state);
  else app.innerHTML = '<div class="msg error">Unknown phase: ' + escHtml(state.phase) + '</div>';
}

function showFlash(type, text) {
  var old = document.getElementById('_flash');
  if (old) old.remove();
  var d = document.createElement('div');
  d.id = '_flash';
  d.className = 'msg ' + type;
  d.textContent = text;
  app.prepend(d);
}

// ---- Editing phase --------------------------------------------------------

function renderEditing(state) {
  const isSaved   = (state.config.mode === 'saved');
  const isRunning = !isSaved;
  const editText  = state.edit_text  || '';
  const liveText  = state.live_text  || '';
  const sidebar   = state.sidebar;

  const runCls = isRunning ? 'tab-btn active' : 'tab-btn';
  const savCls = isSaved   ? 'tab-btn active' : 'tab-btn';

  const logPanelHtml = isRunning ? `
<div class="log-panel" id="log-panel-slot">
<h4>Log Output</h4>
<button type="button" class="btn-neutral btn-sm" id="go-monitor-btn"
  style="margin-bottom:.4em" title="Full view">&#x26F6; Full view</button>
<div id="log-container">
<div class="log-controls">
  <button id="log-toggle" type="button" class="btn-neutral btn-sm">Monitor: off</button>
  <button id="log-clear"  type="button" class="btn-neutral btn-sm">Clear</button>
  <label>Lines: <input id="log-max-input" type="number" value="50" min="10" max="9999"></label>
</div>
<div id="log-output"></div>
</div>
</div>` : '';

  const layoutCls = isRunning ? 'editor-layout editor-layout-bp' : 'editor-layout';

  const modeControls = isSaved
    ? `<input type="hidden" name="mode" value="saved_incremental">
  <p class="mode-hint">Staging applies only the tables in this file incrementally — other tables are left untouched.</p>`
    : `<div><label for="mode-sel">Stage mode: <select id="mode-sel" name="mode">
    <option value="full">Full replacement</option>
    <option value="patch">Patch (incremental)</option>
  </select></label></div>`;

  const saveBtnHtml = isSaved
    ? `<div style="margin-top:.5em"><button type="button" class="btn-neutral" id="save-btn">Save to disk</button></div>` : '';

  const heading = isSaved
    ? `Edit Ruleset — Saved config (${escHtml(state.config.saved_path)})`
    : 'Edit Ruleset — Running config';

  const fetchErrHtml = state.edit_error
    ? `<div class="msg error">${escHtml(state.edit_error)}</div>` : '';

  app.innerHTML = `
<div class="mode-tabs">
  <a href="/" class="${runCls}">Running config</a>
  <a href="/?mode=saved" class="${savCls}">Saved config</a>
  <button id="monitor-tab-btn" class="tab-btn" type="button">Monitor</button>
  <a href="/graph" class="tab-btn">Graph</a>
</div>
<div id="monitor-view" style="display:none"><h2>Monitor</h2></div>
<div id="editor-view" class="${layoutCls}">
${logPanelHtml}
<div>
${fetchErrHtml}<h2>${heading}</h2>
<form id="stage-form">
  ${modeControls}
  <div id="editor"></div>
  <div class="form-btns">
    <button type="button" class="btn-neutral" id="validate-btn">Validate syntax</button>
    <button type="submit">Stage change</button>
  </div>
  <div id="validate-result"></div>
</form>
${saveBtnHtml}
</div>
${buildSidebarHtml(sidebar, isRunning)}
</div>`;

  // In saved mode diff against the saved file itself (not the annotated running config).
  initEditor(editText, isSaved ? editText : liveText, isRunning, isSaved, sidebar);
}

function buildSidebarHtml(sidebar, withLogGroups) {
  if (!sidebar) return '';
  var h = '<aside class="sidebar">\n';

  h += '<h4>Interfaces</h4><ul>\n';
  if (!sidebar.interfaces.length) {
    h += '<li class="sb-empty">None found</li>\n';
  } else {
    for (var i = 0; i < sidebar.interfaces.length; i++) {
      var iface = sidebar.interfaces[i];
      h += '<li><button type="button" class="sb-item" data-insert="' + escHtml('"' + iface + '"') + '">' + escHtml(iface) + '</button></li>\n';
    }
  }
  h += '</ul>\n';

  h += '<h4>Defines</h4><ul>\n';
  if (!sidebar.defines.length) {
    h += '<li class="sb-empty">None</li>\n';
  } else {
    for (var i = 0; i < sidebar.defines.length; i++) {
      var def = sidebar.defines[i];
      h += '<li><button type="button" class="sb-item" data-insert="' + escHtml('$' + def.name) + '" title="' + escHtml(def.value) + '">$' + escHtml(def.name) + '</button></li>\n';
    }
  }
  h += '</ul>\n';

  h += '<h4>Sets</h4><ul>\n';
  if (!sidebar.sets.length) {
    h += '<li class="sb-empty">None</li>\n';
  } else {
    for (var i = 0; i < sidebar.sets.length; i++) {
      var sname = sidebar.sets[i];
      h += '<li><button type="button" class="sb-item" data-insert="' + escHtml('@' + sname) + '">@' + escHtml(sname) + '</button></li>\n';
    }
  }
  h += '</ul>\n';

  h += '<h4>Help</h4>\n<ul class="sb-help">\n';
  h += '  <li><a href="https://wiki.nftables.org/" target="_blank" rel="noopener noreferrer">nftables wiki &#x2197;</a></li>\n';
  h += '  <li><button type="button" class="btn-neutral btn-sm" id="help-toggle">Keyword help: off</button></li>\n';
  h += '</ul>\n';

  if (withLogGroups) {
    h += '<h4>Log Groups</h4>\n';
    h += '<div id="bp-list"><span class="sb-empty">No breakpoints</span></div>\n';
    h += '<p class="hint">Click gutter to toggle</p>\n';
  }

  h += '</aside>\n';
  return h;
}

// ---- Editor init (CM6 + forms + monitor) ---------------------------------

function initEditor(editText, liveText, isRunning, isSaved, sidebar) {
  // Forward refs populated later when monitor setup runs (running mode only).
  var setBreakpoint   = null;
  var clearBreakpoint = null;

  // --- diff decorations ---
  class DiffDelWidget extends WidgetType {
    toDOM() { var d = document.createElement('div'); d.className = 'cm-diff-del'; return d; }
    eq(other) { return other instanceof DiffDelWidget; }
    get estimatedHeight() { return 3; }
  }
  const diffEffect = StateEffect.define();
  const diffField  = StateField.define({
    create: () => Decoration.none,
    update(deco, tr) {
      deco = deco.map(tr.changes);
      for (var e of tr.effects) if (e.is(diffEffect)) deco = e.value;
      return deco;
    },
    provide: f => EditorView.decorations.from(f)
  });

  // --- error-line decorations ---
  const errEffect = StateEffect.define();
  const errField  = StateField.define({
    create: () => Decoration.none,
    update(deco, tr) {
      deco = deco.map(tr.changes);
      for (var e of tr.effects) if (e.is(errEffect)) deco = e.value;
      return deco;
    },
    provide: f => EditorView.decorations.from(f)
  });

  function updateInlineDiff(v) {
    var ops = computeDiff(liveText, v.state.doc.toString());
    var decos = [], docLine = 1;
    for (var op of ops) {
      if (op.t === '=') {
        docLine++;
      } else if (op.t === '+') {
        if (docLine <= v.state.doc.lines)
          decos.push(Decoration.line({ class: 'cm-diff-add' }).range(v.state.doc.line(docLine).from));
        docLine++;
      } else {
        var pos = docLine <= v.state.doc.lines ? v.state.doc.line(docLine).from : v.state.doc.length;
        decos.push(Decoration.widget({ widget: new DiffDelWidget(), block: true, side: -1 }).range(pos));
      }
    }
    v.dispatch({ effects: diffEffect.of(Decoration.set(decos, true)) });
  }

  // --- keyword help ---
  const NFT_HELP = {
    'table':      'Container for chains/sets/maps. Families: ip ip6 inet arp bridge netdev.',
    'chain':      'Ordered rules list. Base chains need hook, priority and policy; regular chains are jump targets.',
    'rule':       'A single match-and-action statement inside a chain.',
    'set':        'Named collection of addresses, ports, or other values for efficient matching.',
    'map':        'Named key→value store for lookups inside rules.',
    'hook':       'Netfilter attachment: prerouting input forward output postrouting ingress egress.',
    'policy':     'Default chain verdict when no rule matches: accept or drop.',
    'priority':   'Controls processing order when multiple chains share a hook. Lower runs first.',
    'type':       'Chain type: filter nat route. Or set/map element type.',
    'accept':     'Verdict: allow the packet to continue through the stack.',
    'drop':       'Verdict: silently discard the packet.',
    'reject':     'Verdict: discard and send an error reply (ICMP unreachable or TCP RST).',
    'return':     'Verdict: stop processing this chain and return to the calling chain.',
    'jump':       'Verdict: process the named chain then return here.',
    'goto':       'Verdict: process the named chain without returning.',
    'iifname':    'Match on incoming interface name (string). Slower than iif but handles dynamic interfaces.',
    'oifname':    'Match on outgoing interface name (string). Slower than oif but handles dynamic interfaces.',
    'iif':        'Match on incoming interface index (integer). Faster than iifname.',
    'oif':        'Match on outgoing interface index (integer). Faster than oifname.',
    'saddr':      'Match on source IP address or prefix.',
    'daddr':      'Match on destination IP address or prefix.',
    'sport':      'Match on source port number or range.',
    'dport':      'Match on destination port number or range.',
    'ct':         'Connection tracking. ct state: new established related invalid untracked.',
    'state':      'ct state values: new established related invalid untracked.',
    'ip':         'IPv4 header fields, or the ip table family.',
    'ip6':        'IPv6 header fields, or the ip6 table family.',
    'inet':       'Dual-stack family covering both IPv4 and IPv6 in one table.',
    'tcp':        'TCP protocol fields: flags dport sport sequence ack-seq window.',
    'udp':        'UDP protocol fields: sport dport length checksum.',
    'icmp':       'ICMPv4 fields: type code id sequence.',
    'icmpv6':     'ICMPv6 fields: type code.',
    'counter':    'Counts matching packets and bytes. Attach to any rule.',
    'log':        'Log matching packets to the kernel log (dmesg/journald). Options: prefix level group.',
    'limit':      'Rate-limit: limit rate N/second burst M packets.',
    'masquerade': 'NAT: rewrite source address to the outgoing interface address (for dynamic IPs).',
    'snat':       'Source NAT: rewrite source to a fixed address. to <addr>.',
    'dnat':       'Destination NAT: redirect to a fixed address. to <addr>[:<port>].',
    'define':     'Assign a symbolic name to a value: define NAME = value. Reference as $NAME.',
    'flush':      'Remove all rules/elements: flush ruleset|table|chain|set <name>.',
    'delete':     'Remove a specific named object from the ruleset.',
    'add':        'Add a table, chain, rule, or set element.',
    'insert':     'Insert a rule at the front of a chain.',
    'replace':    'Replace an existing rule identified by handle number.',
  };
  const kwHelp = hoverTooltip(function(view, pos) {
    var line = view.state.doc.lineAt(pos);
    var text = line.text, off = pos - line.from;
    var start = off, end = off;
    while (start > 0 && /\w/.test(text[start - 1])) start--;
    while (end < text.length && /\w/.test(text[end])) end++;
    if (start === end) return null;
    var word = text.slice(start, end);
    var tip  = NFT_HELP[word];
    if (!tip) return null;
    return { pos: line.from + start, end: line.from + end, above: true, create() {
      var d = document.createElement('div');
      d.className = 'nft-tooltip';
      d.innerHTML = '<strong>' + escHtml(word) + '</strong>: ' + escHtml(tip);
      return { dom: d };
    }};
  });
  const helpComp = new Compartment();

  // --- brace fold ---
  const nftFold = foldService.of(function(state, lineFrom, lineTo) {
    var lineText = state.sliceDoc(lineFrom, lineTo);
    var openIdx  = lineText.lastIndexOf('{');
    if (openIdx < 0) return null;
    var openPos = lineFrom + openIdx;
    var depth = 1, cur = openPos + 1;
    while (cur < state.doc.length && depth > 0) {
      var ch = state.sliceDoc(cur, cur + 1);
      if (ch === '{') depth++;
      else if (ch === '}') { depth--; if (depth === 0) break; }
      cur++;
    }
    if (depth !== 0) return null;
    return { from: openPos + 1, to: state.doc.lineAt(cur).from - 1 };
  });

  // --- breakpoint state (running mode only) ---
  var bpToggle, bpReset, bpField, bpGutter, bpMarker;
  if (isRunning) {
    bpToggle = StateEffect.define({ map: (v, m) => ({pos: m.mapPos(v.pos), on: v.on}) });
    bpReset  = StateEffect.define();

    class BpMarker extends GutterMarker {
      toDOM() {
        var d = document.createElement('div');
        d.className = 'bp-marker';
        d.textContent = '●';
        return d;
      }
    }
    bpMarker = new BpMarker();

    bpField = StateField.define({
      create: () => RangeSet.empty,
      update(set, tr) {
        set = set.map(tr.changes);
        for (var e of tr.effects) {
          if (e.is(bpReset)) return e.value;
          if (e.is(bpToggle)) {
            if (e.value.on) set = set.update({add: [bpMarker.range(e.value.pos)]});
            else { var rm = e.value.pos; set = set.update({filter: f => f !== rm}); }
          }
        }
        return set;
      }
    });

    bpGutter = gutter({
      class: 'cm-bp-gutter',
      markers:        v => v.state.field(bpField),
      initialSpacer:  () => bpMarker,
      domEventHandlers: {
        mousedown(view, line) {
          var pos    = line.from;
          var lineNo = view.state.doc.lineAt(pos).number;
          var has    = false;
          view.state.field(bpField).between(pos, pos, () => { has = true; });
          if (has) { if (clearBreakpoint) clearBreakpoint(view, pos, lineNo - 1); }
          else     { if (setBreakpoint)   setBreakpoint(view, pos, lineNo - 1);   }
          return true;
        }
      }
    });
  }

  // --- build extensions list ---
  var extensions = [
    vim(),
    ...(isRunning ? [bpGutter, bpField] : []),
    basicSetup,
    nftLanguage.extension,
    nftFold,
    helpComp.of([]),
    keymap.of([indentWithTab]),
    diffField,
    errField,
    EditorView.updateListener.of(update => { if (update.docChanged) updateInlineDiff(update.view); }),
  ];

  var view = new EditorView({
    state: EditorState.create({ doc: editText, extensions }),
    parent: document.getElementById('editor')
  });
  updateInlineDiff(view);

  // --- sidebar insert ---
  document.querySelectorAll('.sb-item[data-insert]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      view.dispatch(view.state.replaceSelection(btn.dataset.insert));
      view.focus();
    });
  });

  // --- keyword help toggle ---
  var helpBtn = document.getElementById('help-toggle');
  if (helpBtn) {
    var helpOn = false;
    helpBtn.addEventListener('click', function() {
      helpOn = !helpOn;
      helpBtn.textContent = 'Keyword help: ' + (helpOn ? 'on' : 'off');
      view.dispatch({ effects: helpComp.reconfigure(helpOn ? [kwHelp] : []) });
    });
  }

  // --- error line decorations ---
  function getErrorLines(errText, docText) {
    var el = errText.split('\n'), dl = docText.split('\n'), out = [];
    for (var i = 0; i < el.length - 1; i++) {
      if (/^\s*\^\s*$/.test(el[i + 1])) {
        var src = el[i];
        for (var j = 0; j < dl.length; j++) {
          if ((dl[j] === src || dl[j].trim() === src.trim()) && out.indexOf(j) === -1)
            out.push(j);
        }
      }
    }
    return out;
  }
  function setErrorLines(lineNums) {
    if (!lineNums.length) {
      view.dispatch({ effects: errEffect.of(Decoration.none) }); return;
    }
    var decos = lineNums
      .filter(n => n + 1 <= view.state.doc.lines)
      .map(n => Decoration.line({ class: 'cm-err-line' }).range(view.state.doc.line(n + 1).from))
      .sort((a, b) => a.from - b.from);
    view.dispatch({ effects: errEffect.of(Decoration.set(decos, true)) });
  }

  // --- validate ---
  var valBtn = document.getElementById('validate-btn');
  var valOut = document.getElementById('validate-result');
  valBtn.addEventListener('click', async function() {
    setErrorLines([]);
    valBtn.disabled = true;
    valBtn.textContent = 'Validating…';
    var content = view.state.doc.toString();
    try {
      var resp = await fetch('/validate', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({content})
      });
      var data = await resp.json();
      if (data.ok) {
        valOut.className = 'msg notice'; valOut.textContent = 'Syntax valid ✓'; setErrorLines([]);
      } else {
        var errText = data.error || 'unknown error';
        valOut.className = 'msg error'; valOut.textContent = 'Invalid: ' + errText;
        setErrorLines(getErrorLines(errText, content));
      }
    } catch (e) {
      valOut.className = 'msg error'; valOut.textContent = 'Validation request failed: ' + e;
    } finally {
      valBtn.disabled = false; valBtn.textContent = 'Validate syntax';
    }
  });

  // --- stage form ---
  document.getElementById('stage-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    var content = view.state.doc.toString();
    var mode    = isSaved ? 'saved_incremental'
      : (document.getElementById('mode-sel')?.value || 'full');
    try {
      var resp = await fetch('/stage', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({mode, content})
      });
      var data = await resp.json();
      if (data.ok) { showFlash('notice', data.notice || 'Change staged'); await loadAndRender(); }
      else showFlash('error', data.error || 'Stage failed');
    } catch (e) { showFlash('error', 'Request failed: ' + e); }
  });

  // --- save button (saved mode) ---
  var saveBtn = document.getElementById('save-btn');
  if (saveBtn) {
    saveBtn.addEventListener('click', async function() {
      var content = view.state.doc.toString();
      try {
        var resp = await fetch('/save-config', {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({content})
        });
        var data = await resp.json();
        showFlash(data.ok ? 'notice' : 'error', data.ok ? (data.notice || 'Saved') : (data.error || 'Save failed'));
      } catch (e) { showFlash('error', 'Request failed: ' + e); }
    });
  }

  // --- chain deep-link from graph ---
  (function() {
    var cp = new URLSearchParams(location.search).get('chain');
    if (!cp) return;
    var parts = cp.split('/');
    if (parts.length < 3) return;
    var fam = parts[0], tbl = parts[1], chn = parts[2];
    function reEsc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
    var text   = view.state.doc.toString();
    var tRe    = new RegExp('\\btable\\s+' + reEsc(fam) + '\\s+' + reEsc(tbl) + '\\b');
    var tMatch = tRe.exec(text);
    var fromIdx = tMatch ? tMatch.index : 0;
    var cRe    = new RegExp('\\bchain\\s+' + reEsc(chn) + '\\s*\\{');
    var cMatch = cRe.exec(text.slice(fromIdx));
    if (!cMatch) return;
    var pos = fromIdx + cMatch.index;
    view.dispatch({ selection: { anchor: pos }, effects: EditorView.scrollIntoView(pos, { y: 'center' }) });
  })();

  // --- monitor tab (non-running mode just navigates to /) ---
  if (!isRunning) {
    var mb = document.getElementById('monitor-tab-btn');
    if (mb) mb.onclick = function() { location.href = '/'; };
    return;
  }

  // ---- Monitor + breakpoints (running mode) --------------------------------

  var logEl         = document.getElementById('log-output');
  var logToggle     = document.getElementById('log-toggle');
  var logClear      = document.getElementById('log-clear');
  var logMaxInput   = document.getElementById('log-max-input');
  var logContainer  = document.getElementById('log-container');
  var logPanelSlot  = document.getElementById('log-panel-slot');
  var editorViewEl  = document.getElementById('editor-view');
  var monitorViewEl = document.getElementById('monitor-view');
  var monitorTabBtn = document.getElementById('monitor-tab-btn');
  var goMonitorBtn  = document.getElementById('go-monitor-btn');

  function showBpError(msg) {
    var d = document.createElement('div');
    d.className = 'log-line'; d.style.color = '#f88';
    d.textContent = 'Breakpoint error: ' + msg;
    logEl.appendChild(d); logEl.scrollTop = logEl.scrollHeight;
  }

  var monitorTabActive = false;
  function activateMonitorTab() {
    monitorTabActive = true;
    editorViewEl.style.display = 'none';
    monitorViewEl.appendChild(logContainer);
    monitorViewEl.style.display = '';
    monitorTabBtn.classList.add('active');
  }
  function activateEditorTab() {
    monitorTabActive = false;
    monitorViewEl.style.display = 'none';
    logPanelSlot.appendChild(logContainer);
    editorViewEl.style.display = '';
    monitorTabBtn.classList.remove('active');
  }
  monitorTabBtn.addEventListener('click', function() {
    if (monitorTabActive) activateEditorTab(); else activateMonitorTab();
  });
  goMonitorBtn.addEventListener('click', activateMonitorTab);

  function updateBpSidebar(list) {
    var el = document.getElementById('bp-list');
    if (!list.length) { el.innerHTML = '<span class="sb-empty">No breakpoints</span>'; return; }
    var html = '<ul style="margin:.2em 0;padding:0 0 0 .5em">';
    for (var i = 0; i < list.length; i++) {
      var bp = list[i];
      html += '<li style="padding:.1em 0"><button type="button" class="sb-item" style="color:#c00" data-line="' + bp.line + '">●</button> L' + (bp.line + 1) + ' ' + escHtml(bp.chain_name) + '</li>';
    }
    html += '</ul>';
    el.innerHTML = html;
    el.querySelectorAll('.sb-item[data-line]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var zl  = parseInt(btn.dataset.line);
        var pos = (zl + 1 <= view.state.doc.lines) ? view.state.doc.line(zl + 1).from : 0;
        if (clearBreakpoint) clearBreakpoint(view, pos, zl);
      });
    });
  }

  var evtSource = null;
  function startMonitor() {
    if (evtSource) return;
    evtSource = new EventSource('/log-stream');
    evtSource.onmessage = function(e) {
      var d = document.createElement('div'); d.className = 'log-line'; d.textContent = e.data;
      logEl.appendChild(d);
      var cap = Math.max(10, parseInt(logMaxInput.value) || 50);
      while (logEl.childElementCount > cap) logEl.removeChild(logEl.firstChild);
      logEl.scrollTop = logEl.scrollHeight;
    };
    evtSource.onerror = function() {
      logToggle.textContent = 'Monitor: off'; evtSource.close(); evtSource = null;
    };
    logToggle.textContent = 'Monitor: on';
    localStorage.setItem('fwgui-monitor', '1');
  }
  function stopMonitor() {
    if (!evtSource) return;
    evtSource.close(); evtSource = null; logToggle.textContent = 'Monitor: off';
    localStorage.removeItem('fwgui-monitor');
  }
  logToggle.addEventListener('click', function() { if (evtSource) stopMonitor(); else startMonitor(); });
  logClear.addEventListener('click', function() { logEl.innerHTML = ''; });

  function syncBreakpoints() {
    fetch('/breakpoints').then(r => r.json()).then(function(list) {
      var ranges = [];
      for (var i = 0; i < list.length; i++) {
        var lineNo = list[i].line + 1;
        if (lineNo <= view.state.doc.lines)
          ranges.push(bpMarker.range(view.state.doc.line(lineNo).from));
      }
      ranges.sort((a, b) => a.from - b.from);
      view.dispatch({ effects: bpReset.of(RangeSet.of(ranges, true)) });
      updateBpSidebar(list);
    }).catch(() => {});
  }

  // Populate the forward references used by the gutter handler.
  setBreakpoint = function(v, pos, zeroLine) {
    var isFirst = (v.state.field(bpField).size === 0);
    fetch('/breakpoint', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({line: zeroLine})
    }).then(r => r.json()).then(function(data) {
      if (data.ok) {
        v.dispatch({ effects: bpToggle.of({pos, on: true}) });
        if (isFirst && !evtSource) startMonitor();
        syncBreakpoints();
      } else showBpError(data.error || 'unknown');
    }).catch(e => showBpError(String(e)));
  };
  clearBreakpoint = function(v, pos, zeroLine) {
    fetch('/breakpoint/' + zeroLine, {method: 'DELETE'})
      .then(r => r.json())
      .then(function(data) {
        if (data.ok) { v.dispatch({ effects: bpToggle.of({pos, on: false}) }); syncBreakpoints(); }
        else showBpError(data.error || 'unknown');
      }).catch(() => {});
  };

  if (localStorage.getItem('fwgui-monitor')) startMonitor();
  syncBreakpoints();
}

// ---- Staged phase -------------------------------------------------------

function renderStaged(state) {
  var liveText   = state.live_text   || '';
  var stagedText = state.staged_text || '';

  app.innerHTML = `
<div class="mode-tabs">
  <a href="/" class="tab-btn">Running config</a>
  <a href="/?mode=saved" class="tab-btn">Saved config</a>
  <a href="/graph" class="tab-btn">Graph</a>
</div>
<details>
  <summary>Live ruleset (current)</summary>
  <pre>${escHtml(liveText)}</pre>
</details>
<h2>Staged Change &#8212; ${escHtml(state.staged_mode || '')}</h2>
<div class="msg warn">Review the diff carefully before promoting.</div>
<h3>Diff (live &#8594; staged)</h3>
<div class="diff-view" id="diff-view"></div>
<details class="staged-full">
  <summary>Full staged content</summary>
  <pre>${escHtml(stagedText)}</pre>
</details>
<div class="actions">
  <button type="button" class="btn-danger" id="promote-btn">Promote to live</button>
  <button type="button" id="clear-btn">Clear</button>
</div>`;

  renderDiff(computeDiff(liveText, stagedText), document.getElementById('diff-view'));

  document.getElementById('promote-btn').addEventListener('click', async function() {
    try {
      var resp = await fetch('/promote', {method: 'POST'});
      var data = await resp.json();
      if (data.ok) await loadAndRender();
      else showFlash('error', data.error || 'Promote failed');
    } catch (e) { showFlash('error', 'Request failed: ' + e); }
  });

  document.getElementById('clear-btn').addEventListener('click', async function() {
    try {
      var resp = await fetch('/clear', {method: 'POST'});
      var data = await resp.json();
      if (data.ok) await loadAndRender();
      else showFlash('error', data.error || 'Clear failed');
    } catch (e) { showFlash('error', 'Request failed: ' + e); }
  });
}

// ---- Promoting phase -----------------------------------------------------

function renderPromoting(state) {
  var previousText = state.previous_text || '';
  var promotedText = state.staged_text   || '';
  var deadlineMs   = state.deadline_ms;

  function secsLeft() {
    return deadlineMs ? Math.max(0, Math.round((deadlineMs - Date.now()) / 1000)) : 0;
  }

  app.innerHTML = `
<div class="mode-tabs">
  <a href="/" class="tab-btn">Running config</a>
  <a href="/?mode=saved" class="tab-btn">Saved config</a>
  <a href="/graph" class="tab-btn">Graph</a>
</div>
<div class="msg warn">
  <strong>Change promoted &#8212; auto-rollback in <span id="countdown">${secsLeft()}</span>s.</strong>
  Acknowledge before the timer expires to keep this change.
</div>
<h2>Promoted Change &#8212; ${escHtml(state.staged_mode || '')}</h2>
<h3>Diff (previous &#8594; promoted)</h3>
<div class="diff-view" id="diff-view"></div>
<div class="actions">
  <button type="button" class="btn-safe" id="ack-btn">Acknowledge (keep change)</button>
</div>`;

  renderDiff(computeDiff(previousText, promotedText), document.getElementById('diff-view'));

  var el = document.getElementById('countdown');
  countdownTimer = setInterval(async function() {
    var n = secsLeft();
    el.textContent = String(n);
    if (n <= 0) { clearInterval(countdownTimer); countdownTimer = null; await loadAndRender(); }
  }, 1000);

  document.getElementById('ack-btn').addEventListener('click', async function() {
    if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
    try {
      var resp = await fetch('/acknowledge', {method: 'POST'});
      var data = await resp.json();
      if (data.ok) { showFlash('notice', data.notice || 'Change acknowledged'); await loadAndRender(); }
      else showFlash('error', data.error || 'Acknowledge failed');
    } catch (e) { showFlash('error', 'Request failed: ' + e); }
  });
}

// ---- Bootstrap -----------------------------------------------------------

loadAndRender();
