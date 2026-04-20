use serde_json::Value;
use std::collections::HashSet;
use std::process::Command;

#[derive(Debug, Clone)]
struct ChainInfo {
    family: String,
    table: String,
    name: String,
    hook: String,
    priority: i32,
}

// ---------------------------------------------------------------------------
// Family groups
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum FamilyGroup { Network, Bridge, Arp, Netdev }

impl FamilyGroup {
    fn classify(family: &str) -> Option<Self> {
        match family {
            "ip" | "ip6" | "inet" => Some(Self::Network),
            "bridge"              => Some(Self::Bridge),
            "arp"                 => Some(Self::Arp),
            "netdev"              => Some(Self::Netdev),
            _                     => None,
        }
    }

    fn id(&self) -> &'static str {
        match self { Self::Network=>"network", Self::Bridge=>"bridge", Self::Arp=>"arp", Self::Netdev=>"netdev" }
    }

    fn display(&self) -> &'static str {
        match self { Self::Network=>"ip / ip6 / inet", Self::Bridge=>"bridge", Self::Arp=>"arp", Self::Netdev=>"netdev" }
    }

    fn prefix(&self) -> &'static str {
        match self { Self::Network=>"n", Self::Bridge=>"br", Self::Arp=>"arp", Self::Netdev=>"nd" }
    }

    fn hooks(&self) -> &'static [&'static str] {
        match self {
            Self::Network | Self::Bridge => &["prerouting","input","forward","output","postrouting"],
            Self::Arp                    => &["input","output"],
            Self::Netdev                 => &["ingress","egress"],
        }
    }

    fn cluster_color(&self) -> &'static str {
        match self { Self::Network=>"#334466", Self::Bridge=>"#553366", Self::Arp=>"#336644", Self::Netdev=>"#664433" }
    }

    fn cluster_bg(&self) -> &'static str {
        match self { Self::Network=>"#1a1a2e", Self::Bridge=>"#1e1828", Self::Arp=>"#181e1c", Self::Netdev=>"#221a14" }
    }

    fn font_color(&self) -> &'static str {
        match self { Self::Network=>"#5577aa", Self::Bridge=>"#7755aa", Self::Arp=>"#557766", Self::Netdev=>"#997755" }
    }
}

// Canonical ordering for iteration
const FAMILY_ORDER: &[FamilyGroup] = &[
    FamilyGroup::Network,
    FamilyGroup::Bridge,
    FamilyGroup::Arp,
    FamilyGroup::Netdev,
];

// ---------------------------------------------------------------------------
// Priority parsing and labelling
// ---------------------------------------------------------------------------

const ALL_NAMED: &[(&str, i32)] = &[
    ("raw",      -300),
    ("mangle",   -150),
    ("dstnat",   -100),
    ("filter",      0),
    ("security",   50),
    ("srcnat",    100),
];

fn hook_named_priorities(hook: &str, group: &FamilyGroup) -> &'static [(&'static str, i32)] {
    match group {
        FamilyGroup::Arp | FamilyGroup::Netdev => &[("filter", 0)],
        _ => match hook {
            "prerouting"  => &[("raw",-300),("mangle",-150),("dstnat",-100),("filter",0),("security",50)],
            "input"       => &[("raw",-300),("mangle",-150),("filter",0),("security",50)],
            "forward"     => &[("mangle",-150),("filter",0),("security",50)],
            "output"      => &[("raw",-300),("mangle",-150),("filter",0),("security",50),("srcnat",100)],
            "postrouting" => &[("mangle",-150),("filter",0),("srcnat",100)],
            _             => &[("filter",0)],
        },
    }
}

fn parse_priority(v: &Value) -> Option<i32> {
    match v {
        Value::Number(n) => n.as_i64().map(|x| x as i32),
        Value::String(s) => parse_priority_str(s),
        _ => None,
    }
}

fn parse_priority_str(s: &str) -> Option<i32> {
    let s = s.trim();
    for &(name, base) in ALL_NAMED {
        if s == name { return Some(base); }
        if let Some(rest) = s.strip_prefix(name) {
            let rest = rest.trim();
            if let Some(n) = rest.strip_prefix('+') {
                if let Ok(offset) = n.trim().parse::<i32>() { return Some(base + offset); }
            } else if let Some(n) = rest.strip_prefix('-')
                && let Ok(offset) = n.trim().parse::<i32>() {
                return Some(base - offset);
            }
        }
    }
    None
}

fn priority_label(p: i32, hook: &str, group: &FamilyGroup) -> String {
    let refs = hook_named_priorities(hook, group);
    let &(name, base) = refs.iter().min_by_key(|&&(_, b)| (p - b).abs()).unwrap_or(&("filter", 0));
    let diff = p - base;
    match diff.cmp(&0) {
        std::cmp::Ordering::Equal   => name.to_string(),
        std::cmp::Ordering::Greater => format!("{}+{}", name, diff),
        std::cmp::Ordering::Less    => format!("{}{}", name, diff),
    }
}

// ---------------------------------------------------------------------------
// DOT / HTML label helpers
// ---------------------------------------------------------------------------

fn dot_html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn hook_label(hook: &str, group: &FamilyGroup, chains: &[&ChainInfo]) -> String {
    let refs = hook_named_priorities(hook, group);
    let mut sorted = chains.to_vec();
    sorted.sort_by_key(|c| c.priority);

    let mut rows = String::new();
    rows.push_str(&format!(
        "<TR><TD BGCOLOR=\"#1a2a4a\" ALIGN=\"CENTER\"><B><FONT COLOR=\"#88bbee\">{}</FONT></B></TD></TR>\n",
        hook.to_uppercase()
    ));

    // Merge ghost reference markers and real chains in priority order.
    let (mut ri, mut ci) = (0, 0);
    while ri < refs.len() || ci < sorted.len() {
        let rp = refs.get(ri).map(|&(_, p)| p);
        let cp = sorted.get(ci).map(|c| c.priority);
        if matches!((rp, cp), (Some(rp), Some(cp)) if rp <= cp) || (rp.is_some() && cp.is_none()) {
            rows.push_str(&format!(
                "<TR><TD ALIGN=\"LEFT\"><FONT COLOR=\"#3a4a5a\">-- {} --</FONT></TD></TR>\n",
                refs[ri].0
            ));
            ri += 1;
        } else {
            let c = sorted[ci];
            let plabel = dot_html_escape(&priority_label(c.priority, hook, group));
            let cname  = dot_html_escape(&c.name);
            let chain_id = format!("chain-{}-{}-{}", c.family, c.table, c.name);
            rows.push_str(&format!(
                "<TR><TD ID=\"{chain_id}\" HREF=\"/?mode=running\" ALIGN=\"LEFT\"><FONT COLOR=\"#ccddee\">{cname}  [{plabel}]</FONT></TD></TR>\n"
            ));
            ci += 1;
        }
    }

    format!("<\n<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\" CELLPADDING=\"5\" BGCOLOR=\"#1e2233\" COLOR=\"#3355aa\">\n{rows}</TABLE>\n>")
}

// ---------------------------------------------------------------------------
// Cluster renderers
// ---------------------------------------------------------------------------

fn emit_hook_nodes(group: &FamilyGroup, chains: &[&ChainInfo], dot: &mut String) {
    for &hook in group.hooks() {
        let hook_chains: Vec<&ChainInfo> = chains.iter().copied().filter(|c| c.hook == hook).collect();
        let label = hook_label(hook, group, &hook_chains);
        dot.push_str(&format!(
            "    {}_{} [id=\"hook-{}-{}\" shape=none margin=0 label={label}];\n",
            group.prefix(), hook, group.id(), hook
        ));
    }
}

fn render_network_cluster(group: &FamilyGroup, chains: &[&ChainInfo], dot: &mut String) {
    let p = group.prefix();
    dot.push_str(&format!("    {p}_in    [label=\"Incoming\\nPacket\" shape=oval style=filled fillcolor=\"#1a3050\" fontcolor=\"#aaccff\" color=\"#3366aa\"];\n"));
    dot.push_str(&format!("    {p}_out   [label=\"Outgoing\\nPacket\"  shape=oval style=filled fillcolor=\"#1a3050\" fontcolor=\"#aaccff\" color=\"#3366aa\"];\n"));
    dot.push_str(&format!("    {p}_local [label=\"Local\\nProcess\"    shape=oval style=filled fillcolor=\"#1a3020\" fontcolor=\"#aaffaa\" color=\"#336633\"];\n"));
    emit_hook_nodes(group, chains, dot);
    dot.push_str(&format!("    {p}_in -> {p}_prerouting;\n"));
    dot.push_str(&format!("    {p}_prerouting -> {p}_input   [label=\" local\"];\n"));
    dot.push_str(&format!("    {p}_prerouting -> {p}_forward [label=\" forward\"];\n"));
    dot.push_str(&format!("    {p}_input   -> {p}_local;\n"));
    dot.push_str(&format!("    {p}_local   -> {p}_output;\n"));
    dot.push_str(&format!("    {p}_forward -> {p}_postrouting;\n"));
    dot.push_str(&format!("    {p}_output  -> {p}_postrouting;\n"));
    dot.push_str(&format!("    {p}_postrouting -> {p}_out;\n"));
}

fn render_bridge_cluster(group: &FamilyGroup, chains: &[&ChainInfo], dot: &mut String) {
    let p = group.prefix();
    dot.push_str(&format!("    {p}_in    [label=\"L2 Frame\\nIn\"  shape=oval style=filled fillcolor=\"#2a1840\" fontcolor=\"#ccaaff\" color=\"#664488\"];\n"));
    dot.push_str(&format!("    {p}_out   [label=\"L2 Frame\\nOut\" shape=oval style=filled fillcolor=\"#2a1840\" fontcolor=\"#ccaaff\" color=\"#664488\"];\n"));
    dot.push_str(&format!("    {p}_local [label=\"Local\\nProcess\" shape=oval style=filled fillcolor=\"#1a3020\" fontcolor=\"#aaffaa\" color=\"#336633\"];\n"));
    emit_hook_nodes(group, chains, dot);
    dot.push_str(&format!("    {p}_in -> {p}_prerouting;\n"));
    dot.push_str(&format!("    {p}_prerouting -> {p}_input   [label=\" local\"];\n"));
    dot.push_str(&format!("    {p}_prerouting -> {p}_forward [label=\" forward\"];\n"));
    dot.push_str(&format!("    {p}_input   -> {p}_local;\n"));
    dot.push_str(&format!("    {p}_local   -> {p}_output;\n"));
    dot.push_str(&format!("    {p}_forward -> {p}_postrouting;\n"));
    dot.push_str(&format!("    {p}_output  -> {p}_postrouting;\n"));
    dot.push_str(&format!("    {p}_postrouting -> {p}_out;\n"));
}

fn render_arp_cluster(group: &FamilyGroup, chains: &[&ChainInfo], dot: &mut String) {
    let p = group.prefix();
    dot.push_str(&format!("    {p}_in  [label=\"ARP In\"  shape=oval style=filled fillcolor=\"#182818\" fontcolor=\"#aaddaa\" color=\"#446644\"];\n"));
    dot.push_str(&format!("    {p}_out [label=\"ARP Out\" shape=oval style=filled fillcolor=\"#182818\" fontcolor=\"#aaddaa\" color=\"#446644\"];\n"));
    emit_hook_nodes(group, chains, dot);
    dot.push_str(&format!("    {p}_in -> {p}_input -> {p}_output -> {p}_out;\n"));
}

fn render_netdev_cluster(group: &FamilyGroup, chains: &[&ChainInfo], dot: &mut String) {
    emit_hook_nodes(group, chains, dot);
    // ingress and egress are independent hooks — no edge between them
}

fn render_family(group: &FamilyGroup, chains: &[&ChainInfo], dot: &mut String) {
    dot.push_str(&format!(
        "  subgraph cluster_{} {{\n    label=\"{}\" style=filled fillcolor=\"{}\" color=\"{}\" fontcolor=\"{}\" fontname=\"Courier\" fontsize=11;\n",
        group.id(), group.display(), group.cluster_bg(), group.cluster_color(), group.font_color()
    ));
    match group {
        FamilyGroup::Network => render_network_cluster(group, chains, dot),
        FamilyGroup::Bridge  => render_bridge_cluster(group, chains, dot),
        FamilyGroup::Arp     => render_arp_cluster(group, chains, dot),
        FamilyGroup::Netdev  => render_netdev_cluster(group, chains, dot),
    }
    dot.push_str("  }\n\n");
}

// ---------------------------------------------------------------------------
// Full DOT graph
// ---------------------------------------------------------------------------

fn rank_same(nodes: &[String], dot: &mut String) {
    if nodes.len() > 1 {
        dot.push_str(&format!("  {{ rank=same; {}; }}\n", nodes.join("; ")));
    }
}

fn render_dot(all_chains: &[ChainInfo], active: &[FamilyGroup]) -> String {
    let mut dot = String::new();
    dot.push_str("digraph netfilter {\n");
    dot.push_str("  rankdir=LR;\n");
    dot.push_str("  newrank=true;\n"); // enables rank=same across cluster boundaries
    dot.push_str("  bgcolor=\"#12121e\";\n");
    dot.push_str("  node [fontname=\"Courier\" fontsize=10];\n");
    dot.push_str("  edge [color=\"#5577aa\" fontname=\"Courier\" fontsize=9 fontcolor=\"#8899bb\"];\n\n");

    for group in active {
        let chains: Vec<&ChainInfo> = all_chains.iter()
            .filter(|c| FamilyGroup::classify(&c.family).as_ref() == Some(group))
            .collect();
        render_family(group, &chains, &mut dot);
    }

    // Align shared hook columns across all active families.
    // Standard 5-hook families share prerouting/input/forward/output/postrouting columns.
    for &hook in &["prerouting", "input", "forward", "output", "postrouting"] {
        let nodes: Vec<String> = active.iter()
            .filter(|g| g.hooks().contains(&hook))
            .map(|g| format!("{}_{}", g.prefix(), hook))
            .collect();
        rank_same(&nodes, &mut dot);
    }

    // Align entry/exit columns: net_in / br_in / arp_in / nd_ingress at the left edge,
    // and their counterparts at the right edge.
    let left_nodes: Vec<String> = active.iter().map(|g| match g {
        FamilyGroup::Netdev => format!("{}_ingress", g.prefix()),
        _                   => format!("{}_in",      g.prefix()),
    }).collect();
    let right_nodes: Vec<String> = active.iter().map(|g| match g {
        FamilyGroup::Netdev => format!("{}_egress", g.prefix()),
        _                   => format!("{}_out",    g.prefix()),
    }).collect();
    rank_same(&left_nodes, &mut dot);
    rank_same(&right_nodes, &mut dot);

    dot.push_str("}\n");
    dot
}

// ---------------------------------------------------------------------------
// Chain JSON parsing
// ---------------------------------------------------------------------------

fn parse_chains(json: &str) -> Vec<ChainInfo> {
    let Ok(root) = serde_json::from_str::<Value>(json) else { return vec![]; };
    let Some(items) = root.get("nftables").and_then(|v| v.as_array()) else { return vec![]; };
    let mut chains = vec![];
    for item in items {
        let Some(chain) = item.get("chain") else { continue };
        let Some(hook)  = chain.get("hook").and_then(|v| v.as_str()) else { continue };
        let Some(prio)  = chain.get("prio").and_then(|v| parse_priority(v)) else { continue };
        let family = chain.get("family").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let table  = chain.get("table").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let name   = chain.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        chains.push(ChainInfo { family, table, name, hook: hook.to_string(), priority: prio });
    }
    chains
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build a DOT graph string for the running ruleset.
/// `hidden` — set of family group IDs to exclude from the rendered DOT.
/// Returns `(dot, all_populated_family_ids)` — hidden families are excluded from DOT
/// but still reported so the client can render the full pill bar.
pub fn build_dot(hidden: &HashSet<String>) -> Result<(String, Vec<String>), String> {
    let out = Command::new("nft")
        .args(["-j", "list", "ruleset"])
        .output()
        .map_err(|e| format!("nft exec failed: {e}"))?;
    if !out.status.success() {
        return Err(format!("nft error: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let all_chains = parse_chains(&String::from_utf8_lossy(&out.stdout));

    let populated: Vec<&FamilyGroup> = FAMILY_ORDER.iter()
        .filter(|g| all_chains.iter().any(|c| FamilyGroup::classify(&c.family).as_ref() == Some(g)))
        .collect();

    let all_ids: Vec<String> = populated.iter().map(|g| g.id().to_string()).collect();

    let active: Vec<FamilyGroup> = populated.into_iter()
        .filter(|g| !hidden.contains(g.id()))
        .cloned()
        .collect();

    Ok((render_dot(&all_chains, &active), all_ids))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_priority_integer() {
        assert_eq!(parse_priority(&serde_json::json!(-100)), Some(-100));
        assert_eq!(parse_priority(&serde_json::json!(0)),    Some(0));
        assert_eq!(parse_priority(&serde_json::json!(50)),   Some(50));
    }

    #[test]
    fn parse_priority_named() {
        assert_eq!(parse_priority_str("filter"),  Some(0));
        assert_eq!(parse_priority_str("mangle"),  Some(-150));
        assert_eq!(parse_priority_str("raw"),     Some(-300));
        assert_eq!(parse_priority_str("srcnat"),  Some(100));
    }

    #[test]
    fn parse_priority_named_offset() {
        assert_eq!(parse_priority_str("filter + 10"), Some(10));
        assert_eq!(parse_priority_str("filter - 10"), Some(-10));
        assert_eq!(parse_priority_str("mangle+5"),    Some(-145));
        assert_eq!(parse_priority_str("raw-1"),       Some(-301));
    }

    #[test]
    fn priority_label_exact() {
        assert_eq!(priority_label(0,    "input", &FamilyGroup::Network), "filter");
        assert_eq!(priority_label(-150, "input", &FamilyGroup::Network), "mangle");
        assert_eq!(priority_label(-300, "input", &FamilyGroup::Network), "raw");
    }

    #[test]
    fn priority_label_offset() {
        assert_eq!(priority_label(-10,  "input", &FamilyGroup::Network), "filter-10");
        assert_eq!(priority_label(10,   "input", &FamilyGroup::Network), "filter+10");
        assert_eq!(priority_label(-145, "input", &FamilyGroup::Network), "mangle+5");
        assert_eq!(priority_label(-160, "input", &FamilyGroup::Network), "mangle-10");
    }

    #[test]
    fn parse_chains_skips_regular_chains() {
        let json = r#"{"nftables":[
            {"chain":{"family":"inet","table":"main","name":"input","hook":"input","prio":0}},
            {"chain":{"family":"inet","table":"main","name":"helper"}}
        ]}"#;
        let chains = parse_chains(json);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].name, "input");
    }

    #[test]
    fn classify_families() {
        assert_eq!(FamilyGroup::classify("ip"),     Some(FamilyGroup::Network));
        assert_eq!(FamilyGroup::classify("ip6"),    Some(FamilyGroup::Network));
        assert_eq!(FamilyGroup::classify("inet"),   Some(FamilyGroup::Network));
        assert_eq!(FamilyGroup::classify("bridge"), Some(FamilyGroup::Bridge));
        assert_eq!(FamilyGroup::classify("arp"),    Some(FamilyGroup::Arp));
        assert_eq!(FamilyGroup::classify("netdev"), Some(FamilyGroup::Netdev));
        assert_eq!(FamilyGroup::classify("unknown"),None);
    }

    #[test]
    fn build_dot_hidden_excludes_family() {
        let chains = vec![
            ChainInfo { family: "inet".into(), table: "t".into(), name: "c".into(), hook: "input".into(), priority: 0 },
            ChainInfo { family: "bridge".into(), table: "t".into(), name: "c".into(), hook: "input".into(), priority: 0 },
        ];
        let hidden: HashSet<String> = ["bridge".to_string()].into();
        let active: Vec<FamilyGroup> = FAMILY_ORDER.iter()
            .filter(|g| chains.iter().any(|c| FamilyGroup::classify(&c.family).as_ref() == Some(g)))
            .filter(|g| !hidden.contains(g.id()))
            .cloned()
            .collect();
        let dot = render_dot(&chains, &active);
        assert!(dot.contains("cluster_network"));
        assert!(!dot.contains("cluster_bridge"));
    }
}
