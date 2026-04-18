# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`fwgui` is a Rust/Axum web UI for managing nftables firewall rulesets. It is safety-critical — changes to the firewall can lock out the operator, so the rollback mechanism (promote → acknowledge or auto-revert) must be treated as a hard correctness requirement, not an optional feature.

## Build & Development

```bash
cargo build               # compile
cargo run                 # run dev server
cargo test                # all tests
cargo test <test_name>    # single test
cargo clippy              # lint
cargo fmt                 # format
```

Rust stable channel only — do not use nightly features.

## v0.1 Scope

- Display current running nftables ruleset in the browser
- Stage a ruleset change with nftables syntax validation before applying
- Promote a staged change to the live ruleset
- Auto-rollback: if a promoted change is not acknowledged within a timeout, revert to the previous ruleset automatically

## Architecture (intended)

- **Axum** HTTP server as the entry point
- **nftables integration** via system calls / nft CLI or libnftables bindings — read current ruleset, validate syntax, apply changes, and revert
- **Rollback mechanism**: after promoting a change, start a countdown timer; if the operator doesn't confirm within the window, restore the prior ruleset
- **Packet traversal analyser**: planned feature to simulate what a crafted packet would match in the active ruleset

## Key Constraints

- nftables is the only supported firewall backend
- The rollback acknowledgement flow is a safety invariant — never bypass or make it optional
- Prefer explicit error handling over panics; firewall operations must fail safely
