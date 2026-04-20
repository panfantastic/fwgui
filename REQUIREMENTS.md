# Overview

Firewall web ui to aid in design and implementation of complex firewall rulesets.

# Technology Choices

* language: rust (stable)
* Web framework: axum

# Security concerns
* Supply Chain Attacks are a thing, include the original library as source/binary dependancy versioned rather than call to the internet.
    * npm / python packages are ok as long as referenced and pinned to specific versions
    * I don't the program to ask to fetch from 3rd parties but to host it locally
* No personal info must be included in user-agent calls when downloading files
* Make a commit after a major change or after a one liner or after a change by an operator if it is significant

# Required support
* nftables 
* a way to analyse what a crafted packet would traverse in the firewall

# Expected outcomes

## v0.1

* A webpage that shows the current running nftables ruleset
* Ability to stage a change to the firewall ruleset with validation of syntax
* Ability to promote a change to the firewall ruleset
* Ensure firewall rollback takes place if change promotion isn't acknowledged

## v0.2

* Inline editing of the current ruleset ready for staging
* Visually show edited lines as stageable
* Show diff of staged change
* Validate nftables syntax of staged change

## v0.3 - Usability of editing

* Improve inline editing
    1. full vim emulation is important
* Failed validation shouldn't wipe out changes in the edit box
* Add visible line numbers to help track problems
* Failed validation should highlight line numbers that failed
* Add folding in editor and diff views - in preparation for large rulesets

### Validation for completion

* nft ruleset is visible
* line numbers are visible
* diff in staged change view should mirror the promoted view
* diff should disregard space and tab characters changes when diffing

## v0.4 - help! nftables is difficult

* Add sidebar component that will support quick access to various groups of objects
    1. List of interfaces on system
    2. List of variables the ruleset defines
    3. List of ip-sets
    
* In app documentation and help is needed.  
    1. There should be a link to nftables documentation.
    2. Toggle for overlay help on keywords

### validation

* Tab handling in editor must not lose focus, must indent.  "vim insert mode handles it first for indentation; in normal mode indentWithTab catches it, indents the line, and prevents focus from leaving the editor"

## v0.5 - Add new mode
A new mode is needed as the current running config might contain rules that other services have added.

Use a toggle or tabbed view to switch between the different modes.

### Running config mode
* as already implemented

### Saved config mode

* Load config from /etc/nftables.conf (or configurable location) rather than current running config
* Save config to /etc/nftables.conf (or the configurable location)
* Save backups of non-rollbacked configuration to /etc/nftables.bak/ (or configurable backup location) with a dated-timed filename
* Staging in this mode needs to be handled differently - it needs to do an incremental update on the changed tables along with all defines.
* The original saved config content needs to travel with the staged change so that on acknowledge, it gets written to disk. Rollback must NOT write to disk — only explicit acknowledge should.

## v0.6 - Packet test and trace

Running config mode only. Breakpoints are ephemeral — they inject log statements into the live ruleset and are never written to disk or saved config.

* Breakpoints
    - Enable marking lines in the running config editor as breakpoints via gutter click
    - Marking a line injects `log prefix "fwgui-bp-<line>: "` into that rule before its verdict (via `nft replace rule ... handle <N> <augmented-rule>`), so only packets matching that specific rule are logged — not all packets at that chain position
    - Breakpoint removal restores the original rule by inserting the original before the breakpointed rule then deleting the breakpointed handle (`nft insert rule ... position <N>` + `nft delete rule ... handle <N>`)
    - Server state is only cleared after the nft command succeeds, so a failed clear can be retried
    - Requires `nf_log_inet` (or `nf_log_ipv4`/`nf_log_ipv6`) kernel modules to be loaded for log output to reach the kernel ring buffer
    - Add a panel on the left for logging output
        - Log line cap is configurable live, default 50 lines (old lines evicted FIFO)
        - Log panel is vertically resizable
    - Add to the right side panel a Log Groups section listing active breakpoints with per-breakpoint remove buttons
* Packet detection
    - When toggled, monitor kernel log via `/dev/kmsg` (falling back to `journalctl -f -k`) for `fwgui-bp-` prefixed entries
    - Stream matching log lines to the logging output panel via SSE
    - A self-test marker is written to `/dev/kmsg` on monitor connect to confirm the pipeline is working

### Implementation notes
* `nft -a list ruleset` annotates each rule with `# handle N`; line → handle mapping is used to identify which rule to augment
* Inserting a separate log rule before the target (old approach) was rejected: it logs all traffic reaching that chain position, not just matching traffic
* The `replace rule` approach injects the log statement into the rule itself before the terminal verdict, preserving per-rule match semantics

### validate
* edit ruleset text area must not be empty
* monitor and clear buttons must be clickable
* clicking the gutter to set a breakpoint must work
* only packets matching the breakpointed rule's criteria should appear in the log output
* clearing a breakpoint must stop log output for that rule

## v0.7

Improvement of UI now the core feature set is implemented and working.

* Monitor auto-start
    - Setting a breakpoint should automatically start the monitor **if no other breakpoints are currently active** (i.e. only on the first breakpoint)
    - If the user has manually stopped the monitor, setting additional breakpoints should not restart it

* Monitor tab
    - Add a "Monitor" tab alongside the existing Running / Saved config tabs
    - The tab gives the log output full viewport width for easier reading
    - Where the log panel currently lives in running config mode, add a button to jump to the Monitor tab
    - The Monitor tab is only meaningful in running config mode (breakpoints are running-mode only)

* Readable log format
    - Parse the nft/kernel log line format (`IN= OUT= SRC= DST= PROTO= SPT= DPT=` etc.) into a compact human-readable summary, e.g. `14:32:01  [bp-5: input]  TCP  192.168.1.100:54321 → 10.0.0.1:22  SYN  TTL=64`
    - Regex parsing of nft log fields is the baseline (no extra dependencies)
    - `tshark` may be used as an optional enhancement when available on the system for richer application-layer decode; fall back gracefully to regex parsing if absent

* Reload / restart recovery
    - On **browser reload**, active breakpoints are preserved in the server's in-memory state; `syncBreakpoints()` restores gutter markers and the monitor should auto-restart if breakpoints are active
    - On **server restart**, scan `nft -a list ruleset` at startup for rules containing `fwgui-bp-` and remove them (insert+delete) to clean up stale injected log statements
    - Server-side persistent state (e.g. a state file) is acceptable if it simplifies recovery

## v0.8

UI cleanup of layout inconsistencies

* Replace scattered inline styles with named CSS classes throughout
* Add `.btn-sm` for consistent small button sizing across log controls, sidebar help, and monitor button
* Add `.log-controls` flex container to normalise log panel controls layout
* Add `.form-btns` flex container for editor action buttons (Validate / Stage)
* Make `.actions` a flex container so Promote/Clear and Acknowledge buttons have consistent spacing without inline `display:inline` on forms
* Move monitor view padding and h2 margin to CSS (`#monitor-view`, `#monitor-view h2`)
* Add `.sb-help`, `.hint`, `.mode-hint`, `.staged-full`, `.save-inline` classes to replace remaining inline styles
* Remove `<br>` from running-mode controls; use a wrapping `<div>` instead
* Add `font-family: inherit` to global button rule so all buttons use the page monospace font
* Fix Monitor tab alignment: `margin: 0 0 -2px` on `.tab-btn` overrides the global `button` margin so the Monitor `<button>` tab sits flush with the `<a>` tabs
* Set `background: transparent` on `.tab-btn` to suppress the browser UA button background

## v0.9

* nftables syntax highlighting in the CodeMirror editor
    - Implement a custom `StreamLanguage` tokenizer for nftables
    - Highlight: keywords (table, chain, rule, type, hook, policy, etc.), address families (ip, ip6, inet, arp, bridge, netdev), verdict statements (accept, drop, reject, return, continue, goto, jump), string literals, numeric literals (including hex/CIDR), comments (`#`), and operators/punctuation
    - Highlighting applies to the editing view (both running and saved config modes); diff views are read-only and do not require it

## v0.10 — Graph view

Interactive graph visualisation of the running ruleset mapped onto the Linux netfilter traversal.

### Structure

* Follows the Jan Engelhardt netfilter packet flow diagram (INPUT PATH / FORWARD PATH / OUTPUT PATH)
* Scope for v0.10: Network Layer hooks only (ip/ip6/inet) — bridge/ARP/netdev are future work
* Five hook nodes: PREROUTING → INPUT / FORWARD → POSTROUTING, with LOCAL PROCESS between INPUT and OUTPUT
* Each hook node contains the user's base chains attached to that hook, sorted by priority
* Ghost reference rows mark the canonical named priority positions within each hook node so
  out-of-place chains are visually obvious

### Priority display

* Chains display priority relative to the nearest named symbolic priority:
  `mangle+5`, `filter−10`, `raw` (exact), not raw integers
* Named priorities per hook:
  - prerouting: raw(−300), mangle(−150), dstnat(−100), filter(0), security(50)
  - input / forward: raw(−300)*, mangle(−150), filter(0), security(50)  *(input only)
  - output: raw(−300), mangle(−150), filter(0), security(50), srcnat(100)
  - postrouting: mangle(−150), filter(0), srcnat(100)

### Technology

* Server generates a DOT/Graphviz string via `GET /api/graph/dot` (reads `nft -j list ruleset`)
* `nft -j` priority field handled in all three forms: integer, named string (`"filter"`),
  named+offset string (`"filter + 10"`)
* Client renders DOT → SVG using `@viz-js/viz` (Graphviz compiled to WASM, inline bundle)
* Pan/zoom via `@panzoom/panzoom`; initial render fits the graph to the viewport
* SVG is sized to 100%×100% of the container; the SVG's own `viewBox` +
  `preserveAspectRatio="xMidYMid meet"` (SVG default) centres and letterboxes the content
  without any manual scale/pan calculation — panzoom starts at scale=1, pan=(0,0)
* Fit button and post-render reset call `pz.zoom(1); pz.pan(0,0)` to restore the initial view
* Separate JS bundle (`graph-bundle.js`) keeps the editor page free of the ~2 MB WASM payload

### Validation

* Graph tab visible from any page state (links to `/graph`)
* Graph renders for a ruleset with no user chains (shows ghost reference rows only)
* Graph renders for chains at canonical priorities, between canonical priorities, and far outside them
* Pan and pinch-zoom work; scroll-wheel zooms
* Zoom-out must allow the graph to shrink well below the viewport size (minScale 0.01, no contain constraint)
* On load, the full graph is visible and centred in the viewport with no content off-screen
* Chains at non-standard priorities visually stand out relative to ghost markers

## v0.10.1 — Multi-layer graph, collapse/expand, clickable chains

### Protocol layers

* Extend the graph to show all nftables address families, each as a horizontal row:
  - `ip / ip6 / inet` — prerouting → input/forward → output → postrouting (same as v0.10)
  - `bridge` — same 5-hook structure; distinct cluster colour
  - `arp` — input → output only
  - `netdev` — ingress (far left) and egress (far right) only
* Only families with at least one base chain are rendered — empty families produce no row
* Hook columns are aligned across rows using `rank=same` with `newrank=true` so the grid
  matches the Engelhardt layered diagram
* Each family is a `subgraph cluster_*` with its own background colour and border

### Collapse / expand

* Populated families appear as toggle pills in the graph toolbar (e.g. `ip/ip6/inet`, `bridge`)
* Each pill is active (visible) by default; clicking hides that family row
* Hiding re-fetches `GET /api/graph/dot?hide=bridge,arp` and re-renders — full re-layout,
  no visual gaps
* The endpoint returns all populated family IDs in an `X-Graph-Families` response header
  so the JS can build the pill bar without a separate API call
* Panzoom fits to view after each re-render

### Clickable chains

* Each chain row `<TD>` in the DOT HTML label carries:
  - `HREF="/?mode=running"` — clicking navigates to the running-config editor (same tab)
  - `ID="chain-{family}-{table}-{name}"` — stable DOM ID for future packet-path highlighting
* Hook nodes carry `id="hook-{family_group}-{hook}"` for future traversal-edge highlighting
* These IDs are the packet-path API surface: a future `/api/graph/dot?path=inet/main/input,...`
  query param can add CSS classes to those elements without re-architecting the pipeline

### Implementation notes

* `GET /api/graph/dot` accepts optional `hide` query param (comma-separated family IDs)
* `build_dot(hidden)` returns `(dot_string, all_populated_family_ids)` — hidden families are
  excluded from the DOT but still reported so the pill bar shows all toggles
* Panzoom instance is destroyed and re-created on each re-render; wheel listener is tracked
  and removed to avoid stacking duplicates
* SVG sizing: `width="100%" height="100%"` fills the container; the SVG viewBox centres the
  content — do not attempt to compute manual pan offsets, as Graphviz outputs pt units which
  differ from CSS pixels and panzoom's coordinate model varies by transform style

### Validation

* A ruleset with only inet chains: single row, no pills for bridge/arp/netdev
* A ruleset with inet + bridge chains: two rows aligned at hook columns, two pills
* Hiding a family row removes it cleanly; showing it restores it
* Clicking a chain row navigates to the editor with the chain definition scrolled into view
* Chain TD IDs are present in the rendered SVG DOM
* On load and after reload/pill toggle, the full graph is centred and fully visible — no content clipped by the left or right edge

## v0.10.2 — Chain deep-link and config-mode toggle

### Chain deep-link

* Clicking a chain node in the graph navigates to the config editor and scrolls the
  editor to the chain's definition line, placing the cursor there
* The URL carries the chain identity as `/?mode=<mode>&chain=<family>/<table>/<name>`,
  e.g. `/?mode=running&chain=inet/filter/input`
* On editor load, the `chain` URL param is read; the editor searches for `table <family> <table>`
  first to resolve the correct block, then `chain <name> {` within it, and scrolls that line
  to the centre of the viewport with the cursor placed at the chain keyword
* If the chain is not found in the current editor content (e.g. the config has changed since
  the graph was rendered), navigation still succeeds but no scroll occurs — no error is shown

### Config-mode toggle

* The graph toolbar carries a toggle button (default: **Running**) controlling which config
  mode chain links open: Running config (`/?mode=running`) or Saved config (`/?mode=saved`)
* The selected mode persists in `localStorage` across page reloads
* Toggling the button does not re-render the graph — it only affects subsequent link clicks

### Implementation notes

* Chain HREF in DOT is `/?chain=family/table/name` (no `mode`) — the graph page JS
  intercepts all SVG `<a>` clicks, injects `?mode=<linkMode>`, and navigates
* Graphviz SVG `<a>` elements may use `xlink:href` (older Graphviz) or `href` (newer);
  the interceptor checks both attributes
* Table–chain disambiguation: the editor search anchors to `table <family> <table>` before
  searching for `chain <name> {`, so chains with the same name in different tables resolve
  correctly

### Validation

* Clicking a chain in the graph opens the editor with that chain definition centred and the cursor on it
* Toggle button cycles Running ↔ Saved; clicking a chain after toggling opens the correct mode
* Toggle state survives a page reload
* Navigating to a chain that no longer exists in the config does not produce an error

