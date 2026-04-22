# CLAUDE.md

## Project

`fwgui` is a Rust/Axum web UI for managing nftables firewall rulesets.

## Build & Development

```bash
cargo build                              # compile (runs npm/vite via build.rs)
SKIP_JS_BUILD=1 cargo build              # skip JS build (bundles are committed)
cargo run                                # run server
FWGUI_DEV=1 SKIP_JS_BUILD=1 cargo run   # dev mode: JS proxied to Vite at localhost:5173
cd ui && npm run dev                     # Vite HMR (used alongside FWGUI_DEV)
cargo test                               # all tests
cargo clippy                             # lint
cargo fmt                                # format
```

## Implemented (v0.1–v0.10.3)

- Running config mode: live ruleset visible and editable, vim keybindings, stage/promote/rollback with countdown
- Saved config mode: loads/saves `/etc/nftables.conf`; incremental per-table staging; rollback never writes to disk
- Syntax validation with error-line highlighting; code folding; nftables syntax highlighting
- Sidebar: lists interfaces, variables, and IP sets defined in the ruleset
- Breakpoints: gutter-click injects log rules into the live ruleset; SSE streams matching kernel log lines to the browser
- Graph view: Graphviz DOT rendered via WASM, shows netfilter traversal for all address families; chains are clickable and deep-link to the editor
- Frontend/backend separation: Rust serves a JSON API; all HTML/CSS/JS lives in `ui/src/`; Vite bundles via `build.rs`

## Safety invariants

These outcomes must remain true at all times:

- A promoted change that is not acknowledged within the timeout always reverts to the prior ruleset
- Rollback in saved config mode never writes to disk — only an explicit acknowledge does
- Breakpoints are ephemeral: never written to saved config or `/etc/nftables.conf`
- A failed breakpoint clear leaves server state unchanged so it can be retried
- nft commands fail explicitly; errors surface to the operator

## Architecture

- **Backend**: Rust/Axum, JSON API — `/api/state` (GET), `/stage` `/promote` `/acknowledge` `/clear` `/save-config` (POST, return `{ok, error?, notice?}`), `/log-stream` (SSE), `/api/graph/dot` (GET)
- **Frontend**: `ui/src/editor.js` (CodeMirror 6, vim, breakpoints, SSE monitor), `ui/src/graph.js` (Viz.js WASM, panzoom); Vite multi-entry build → `static/editor-bundle.js` + `static/graph-bundle.js` (committed to repo)
- **Build**: `build.rs` runs Vite automatically; `SKIP_JS_BUILD=1` skips it for deployment machines; `FWGUI_DEV=1` proxies bundle requests to the Vite dev server
- **Builds on Rust stable** — no nightly features
