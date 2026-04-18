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
* Make a commit after a major change or after a one liner or after a change by an operator

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

### Validation for completion

* nft ruleset is visible
* line numbers are visible


