use serde_json::Value;
use std::process::Command;

#[derive(Debug, Clone)]
struct ChainInfo {
    family: String,
    table: String,
    name: String,
    hook: String,
    priority: i32,
}

// Named symbolic priorities per netfilter hook.
// Only includes priorities that are meaningful at each hook.
fn hook_named_priorities(hook: &str) -> &'static [(&'static str, i32)] {
    match hook {
        "prerouting"  => &[("raw", -300), ("mangle", -150), ("dstnat", -100), ("filter", 0), ("security", 50)],
        "input"       => &[("raw", -300), ("mangle", -150), ("filter", 0), ("security", 50)],
        "forward"     => &[("mangle", -150), ("filter", 0), ("security", 50)],
        "output"      => &[("raw", -300), ("mangle", -150), ("filter", 0), ("security", 50), ("srcnat", 100)],
        "postrouting" => &[("mangle", -150), ("filter", 0), ("srcnat", 100)],
        _             => &[("filter", 0)],
    }
}

// All named priorities for parsing any hook's priority string.
const ALL_NAMED: &[(&str, i32)] = &[
    ("raw",      -300),
    ("mangle",   -150),
    ("dstnat",   -100),
    ("filter",      0),
    ("security",   50),
    ("srcnat",    100),
];

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
        if s == name {
            return Some(base);
        }
        // "name + N" or "name+N" (with or without spaces)
        if let Some(rest) = s.strip_prefix(name) {
            let rest = rest.trim();
            if let Some(n) = rest.strip_prefix('+') {
                if let Ok(offset) = n.trim().parse::<i32>() {
                    return Some(base + offset);
                }
            } else if let Some(n) = rest.strip_prefix('-')
                && let Ok(offset) = n.trim().parse::<i32>() {
                return Some(base - offset);
            }
        }
    }
    None
}

fn priority_label(p: i32, hook: &str) -> String {
    let refs = hook_named_priorities(hook);
    let &(best_name, best_base) = refs.iter()
        .min_by_key(|&&(_, b)| (p - b).abs())
        .unwrap_or(&("filter", 0));
    let diff = p - best_base;
    match diff.cmp(&0) {
        std::cmp::Ordering::Equal   => best_name.to_string(),
        std::cmp::Ordering::Greater => format!("{}+{}", best_name, diff),
        std::cmp::Ordering::Less    => format!("{}{}", best_name, diff),
    }
}

fn dot_html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

fn hook_label(hook: &str, chains: &[ChainInfo]) -> String {
    let refs = hook_named_priorities(hook);
    let mut sorted = chains.to_vec();
    sorted.sort_by_key(|c| c.priority);

    let mut rows = String::new();

    // Header row
    rows.push_str(&format!(
        "<TR><TD BGCOLOR=\"#1a2a4a\" ALIGN=\"CENTER\"><B><FONT COLOR=\"#88bbee\">{}</FONT></B></TD></TR>\n",
        hook.to_uppercase()
    ));

    // Merge ghost reference rows and real chain rows in priority order.
    // A reference marker is emitted when its priority ≤ the next chain priority
    // (i.e. the marker labels the boundary the chain falls at or after).
    let mut ri = 0;
    let mut ci = 0;
    while ri < refs.len() || ci < sorted.len() {
        let rp = refs.get(ri).map(|&(_, p)| p);
        let cp = sorted.get(ci).map(|c| c.priority);
        let emit_ref = match (rp, cp) {
            (Some(rp), Some(cp)) => rp <= cp,
            (Some(_), None)      => true,
            _                    => false,
        };
        if emit_ref {
            let rname = refs[ri].0;
            rows.push_str(&format!(
                "<TR><TD ALIGN=\"LEFT\"><FONT COLOR=\"#3a4a5a\">-- {rname} --</FONT></TD></TR>\n"
            ));
            ri += 1;
        } else {
            let c = &sorted[ci];
            let plabel = dot_html_escape(&priority_label(c.priority, hook));
            let cname  = dot_html_escape(&format!("{}/{}/{}", c.family, c.table, c.name));
            rows.push_str(&format!(
                "<TR><TD ALIGN=\"LEFT\"><FONT COLOR=\"#ccddee\">{cname}  [{plabel}]</FONT></TD></TR>\n"
            ));
            ci += 1;
        }
    }

    format!(
        "<\n<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\" CELLPADDING=\"5\" BGCOLOR=\"#1e2233\" COLOR=\"#3355aa\">\n{rows}</TABLE>\n>"
    )
}

fn parse_chains(json: &str) -> Vec<ChainInfo> {
    let Ok(root) = serde_json::from_str::<Value>(json) else {
        return vec![];
    };
    let Some(items) = root.get("nftables").and_then(|v| v.as_array()) else {
        return vec![];
    };
    let mut chains = vec![];
    for item in items {
        let Some(chain) = item.get("chain") else { continue };
        // Only base chains (attached to a hook) are relevant for the graph.
        let Some(hook_val) = chain.get("hook") else { continue };
        let Some(hook) = hook_val.as_str() else { continue };
        let Some(prio_val) = chain.get("prio") else { continue };
        let Some(priority) = parse_priority(prio_val) else { continue };
        let family = chain.get("family").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let table  = chain.get("table").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let name   = chain.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        chains.push(ChainInfo { family, table, name, hook: hook.to_string(), priority });
    }
    chains
}

fn render_dot(chains: &[ChainInfo]) -> String {
    let hooks = ["prerouting", "input", "forward", "output", "postrouting"];

    let mut dot = String::new();
    dot.push_str("digraph netfilter {\n");
    dot.push_str("  rankdir=LR;\n");
    dot.push_str("  bgcolor=\"#12121e\";\n");
    dot.push_str("  node [fontname=\"Courier\" fontsize=10];\n");
    dot.push_str("  edge [color=\"#5577aa\" fontname=\"Courier\" fontsize=9 fontcolor=\"#8899bb\"];\n\n");

    // Packet entry/exit and local process nodes
    dot.push_str("  net_in   [label=\"Incoming\\nPacket\" shape=oval style=filled fillcolor=\"#1a3050\" fontcolor=\"#aaccff\" color=\"#3366aa\"];\n");
    dot.push_str("  net_out  [label=\"Outgoing\\nPacket\"  shape=oval style=filled fillcolor=\"#1a3050\" fontcolor=\"#aaccff\" color=\"#3366aa\"];\n");
    dot.push_str("  local_proc [label=\"Local\\nProcess\" shape=oval style=filled fillcolor=\"#1a3020\" fontcolor=\"#aaffaa\" color=\"#336633\"];\n\n");

    // Hook nodes with embedded chain tables
    for hook in &hooks {
        let hook_chains: Vec<ChainInfo> = chains.iter()
            .filter(|c| c.hook == *hook)
            .cloned()
            .collect();
        let label = hook_label(hook, &hook_chains);
        dot.push_str(&format!("  {hook} [shape=none margin=0 label={label}];\n"));
    }
    dot.push('\n');

    // Traversal edges
    dot.push_str("  net_in -> prerouting;\n");
    dot.push_str("  prerouting -> input [label=\" local\"];\n");
    dot.push_str("  prerouting -> forward [label=\" forward\"];\n");
    dot.push_str("  input -> local_proc;\n");
    dot.push_str("  local_proc -> output;\n");
    dot.push_str("  forward -> postrouting;\n");
    dot.push_str("  output -> postrouting;\n");
    dot.push_str("  postrouting -> net_out;\n");
    dot.push_str("}\n");
    dot
}

pub fn build_dot() -> Result<String, String> {
    let out = Command::new("nft")
        .args(["-j", "list", "ruleset"])
        .output()
        .map_err(|e| format!("nft exec failed: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("nft error: {stderr}"));
    }
    let json = String::from_utf8_lossy(&out.stdout);
    let chains = parse_chains(&json);
    Ok(render_dot(&chains))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_priority_integer() {
        assert_eq!(parse_priority(&serde_json::json!(-100)), Some(-100));
        assert_eq!(parse_priority(&serde_json::json!(0)), Some(0));
        assert_eq!(parse_priority(&serde_json::json!(50)), Some(50));
    }

    #[test]
    fn parse_priority_named() {
        assert_eq!(parse_priority_str("filter"), Some(0));
        assert_eq!(parse_priority_str("mangle"), Some(-150));
        assert_eq!(parse_priority_str("raw"), Some(-300));
        assert_eq!(parse_priority_str("srcnat"), Some(100));
    }

    #[test]
    fn parse_priority_named_offset() {
        assert_eq!(parse_priority_str("filter + 10"), Some(10));
        assert_eq!(parse_priority_str("filter - 10"), Some(-10));
        assert_eq!(parse_priority_str("mangle+5"), Some(-145));
        assert_eq!(parse_priority_str("raw-1"), Some(-301));
    }

    #[test]
    fn priority_label_exact() {
        assert_eq!(priority_label(0, "input"), "filter");
        assert_eq!(priority_label(-150, "input"), "mangle");
        assert_eq!(priority_label(-300, "input"), "raw");
    }

    #[test]
    fn priority_label_offset() {
        assert_eq!(priority_label(-10, "input"), "filter-10");
        assert_eq!(priority_label(10, "input"), "filter+10");
        assert_eq!(priority_label(-145, "input"), "mangle+5");
        assert_eq!(priority_label(-160, "input"), "mangle-10");
    }

    #[test]
    fn parse_chains_empty() {
        let json = r#"{"nftables":[{"metainfo":{"version":"1.0"}}]}"#;
        assert!(parse_chains(json).is_empty());
    }

    #[test]
    fn parse_chains_base_and_regular() {
        // Regular chain (no hook) should be ignored; base chain should be included.
        let json = r#"{
            "nftables": [
                {"chain": {"family":"inet","table":"main","name":"input","hook":"input","prio":0}},
                {"chain": {"family":"inet","table":"main","name":"helper"}}
            ]
        }"#;
        let chains = parse_chains(json);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].name, "input");
    }
}
