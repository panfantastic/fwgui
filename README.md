# fwgui

A web UI for managing nftables firewall rulesets.

## Features

- View and edit the running nftables ruleset in-browser with vim keybindings
- Stage, validate, and promote changes with automatic rollback if not acknowledged
- Saved config mode (`/etc/nftables.conf`) with incremental per-table staging
- Breakpoint tracing — mark rules in the running config to log matching packets live
- SSE-streamed log output with human-readable packet summaries

## Requirements

- Rust (stable)
- nftables (`nft`)
- `nf_log_inet` kernel module (or `nf_log_ipv4`/`nf_log_ipv6`) for breakpoint packet logging
- Node.js + npm (only needed to rebuild the JS bundles; not required on deployment machines)

## Building

The JS bundles (`static/editor-bundle.js`, `static/graph-bundle.js`) are committed to the
repository, so a full build only requires Rust:

```bash
SKIP_JS_BUILD=1 cargo build --release
```

To rebuild the JS bundles (after editing `ui/src/`):

```bash
cargo build --release   # runs npm install + vite build automatically via build.rs
# or manually:
./build.sh
```

## Running

```bash
# Deployment machine (no Node.js required — uses committed bundles)
SKIP_JS_BUILD=1 cargo run

# Or run the pre-built binary directly
PORT=3000 ROLLBACK_SECS=30 NFT_CONFIG_PATH=/etc/nftables.conf ./target/release/fwgui
```

## Development

For frontend development with Vite HMR:

```bash
# Terminal 1 — Vite dev server
cd ui && npm install && npm run dev

# Terminal 2 — Rust backend (proxies JS requests to Vite)
FWGUI_DEV=1 SKIP_JS_BUILD=1 cargo run
```

Changes to `ui/src/` are reflected immediately without restarting the Rust server.

## Acknowledgements

Conceived and designed by Iain Grant. Implemented with the assistance of
[Claude Sonnet 4.6](https://www.anthropic.com) (Anthropic).
