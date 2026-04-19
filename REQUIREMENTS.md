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
    - Parse the nft/kernel log line format (`IN= OUT= SRC= DST= PROTO= SPT= DPT=` etc.) into a compact human-readable summary, e.g. `TCP 192.168.1.100:54321 → 10.0.0.1:22  [fwgui-bp-5]`
    - `tshark` is an acceptable required or optional dependency if it significantly improves parse quality
    - If `tshark` is present, use it for deeper packet decode; fall back to regex parsing of the nft log fields if not

* Reload / restart recovery
    - On **browser reload**, active breakpoints are preserved in the server's in-memory state; `syncBreakpoints()` restores gutter markers and the monitor should auto-restart if breakpoints are active
    - On **server restart**, scan `nft -a list ruleset` at startup for rules containing `fwgui-bp-` and remove them (insert+delete) to clean up stale injected log statements
    - Server-side persistent state (e.g. a state file) is acceptable if it simplifies recovery

