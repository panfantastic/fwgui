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

Running config mode only. Breakpoints are ephemeral — they inject log rules into the live ruleset and are never written to disk or saved config.

* Breakpoints
    - Enable marking lines in the running config editor as breakpoints
    - Marking a line inserts a `log prefix "fwgui-bp-<handle>: " flags all` rule before that rule's handle (via `nft insert rule ... position <handle>`)
    - Breakpoint removal deletes the injected log rule by its handle
    - Add a second side panel on the left for logging output
    - Add to the right side panel a Log Groups section listing active breakpoints
* Packet detection
    - When toggled, monitor kernel log (journald / /proc/kmsg) for `fwgui-bp-` prefixed entries
    - Stream matching log lines to the logging output side panel via SSE

### validate
* edit ruleset text area must not be empty
* monitor and clear buttons must be clickable
* clicking the gutter to set a breakpoint must work
