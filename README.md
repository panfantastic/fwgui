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

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run
# or
PORT=3000 ROLLBACK_SECS=30 NFT_CONFIG_PATH=/etc/nftables.conf ./target/release/fwgui
```

## Acknowledgements

Conceived and designed by Iain Grant. Implemented with the assistance of
[Claude Sonnet 4.6](https://www.anthropic.com) (Anthropic).
