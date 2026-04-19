use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

pub use nftables::schema::Nftables as NftablesSchema;

#[derive(Debug)]
pub enum NftError {
    Io(std::io::Error),
    Nft(String),
    Json(serde_json::Error),
}

impl std::fmt::Display for NftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NftError::Io(e) => write!(f, "I/O error: {e}"),
            NftError::Nft(msg) => write!(f, "{msg}"),
            NftError::Json(e) => write!(f, "JSON error: {e}"),
        }
    }
}

impl From<std::io::Error> for NftError {
    fn from(e: std::io::Error) -> Self {
        NftError::Io(e)
    }
}

impl From<serde_json::Error> for NftError {
    fn from(e: serde_json::Error) -> Self {
        NftError::Json(e)
    }
}

/// Current ruleset as human-readable text for display.
pub fn get_ruleset_text() -> Result<String, NftError> {
    let out = Command::new("nft").args(["list", "ruleset"]).output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(NftError::Nft(String::from_utf8_lossy(&out.stderr).into_owned()))
    }
}

/// Ruleset text with `# handle N` annotations on each rule (via `nft -a list ruleset`).
pub fn get_ruleset_annotated() -> Result<String, NftError> {
    let out = Command::new("nft").args(["-a", "list", "ruleset"]).output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(NftError::Nft(String::from_utf8_lossy(&out.stderr).into_owned()))
    }
}

/// Identity of a single nftables rule: where it lives and its handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHandle {
    pub table_family: String,
    pub table_name: String,
    pub chain_name: String,
    pub handle: u64,
}

/// Parse the output of `nft -a list ruleset` and return a map of
/// 0-based line number → RuleHandle for every rule line that carries a handle.
/// Chain type declarations, policy lines, set blocks, and closing braces are skipped.
pub fn parse_ruleset_handles(text: &str) -> std::collections::HashMap<usize, RuleHandle> {
    let mut map = std::collections::HashMap::new();
    let mut depth: i32 = 0;
    let mut table_family = String::new();
    let mut table_name = String::new();
    let mut chain_name = String::new();

    for (lineno, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        let opens = trimmed.chars().filter(|&c| c == '{').count() as i32;
        let closes = trimmed.chars().filter(|&c| c == '}').count() as i32;

        if depth == 0 && trimmed.starts_with("table ") {
            let rest = &trimmed["table ".len()..];
            let mut tokens = rest.split_ascii_whitespace();
            if let (Some(fam), Some(nam)) = (tokens.next(), tokens.next()) {
                table_family = fam.to_string();
                table_name = nam.trim_end_matches(|c: char| c == '{' || c.is_ascii_whitespace()).to_string();
            }
        } else if depth == 1 && trimmed.starts_with("chain ") {
            let rest = &trimmed["chain ".len()..];
            chain_name = rest.split_ascii_whitespace().next().unwrap_or("").to_string();
        } else if depth == 2 && !trimmed.is_empty() && !trimmed.starts_with('}') {
            let skip = trimmed.starts_with('#')
                || trimmed.starts_with("type ")
                || trimmed.starts_with("policy ")
                || trimmed.starts_with("set ")
                || trimmed.starts_with("map ");
            if !skip {
                if let Some(h) = extract_handle(trimmed) {
                    map.insert(lineno, RuleHandle {
                        table_family: table_family.clone(),
                        table_name: table_name.clone(),
                        chain_name: chain_name.clone(),
                        handle: h,
                    });
                }
            }
        }

        depth = (depth + opens - closes).max(0);
    }
    map
}

/// Insert a `log` rule before `rule.handle` in the live ruleset.
/// Uses `nft -a -e insert rule ... position <handle>` so the new handle is echoed back.
/// Returns the handle of the newly inserted log rule.
pub fn insert_breakpoint(rule: &RuleHandle, bp_label: &str) -> Result<u64, NftError> {
    let prefix = format!("\"fwgui-bp-{bp_label}: \"");
    let out = Command::new("nft")
        .args([
            "-a", "-e",
            "insert", "rule",
            &rule.table_family, &rule.table_name, &rule.chain_name,
            "position", &rule.handle.to_string(),
            "log", "prefix", &prefix, "flags", "all",
        ])
        .output()?;
    if out.status.success() {
        let text = String::from_utf8_lossy(&out.stdout);
        extract_handle(text.trim())
            .ok_or_else(|| NftError::Nft("could not parse new rule handle from nft echo".into()))
    } else {
        Err(NftError::Nft(String::from_utf8_lossy(&out.stderr).into_owned()))
    }
}

/// Delete a breakpoint log rule by its handle.
pub fn remove_breakpoint(rule: &RuleHandle, log_handle: u64) -> Result<(), NftError> {
    let out = Command::new("nft")
        .args([
            "delete", "rule",
            &rule.table_family, &rule.table_name, &rule.chain_name,
            "handle", &log_handle.to_string(),
        ])
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(NftError::Nft(String::from_utf8_lossy(&out.stderr).into_owned()))
    }
}

fn extract_handle(line: &str) -> Option<u64> {
    let idx = line.rfind("# handle ")?;
    line[idx + "# handle ".len()..].split_ascii_whitespace().next()?.parse().ok()
}

/// Current ruleset as structured JSON — foundation for the packet analyser.
#[allow(dead_code)]
pub fn get_ruleset_json() -> Result<NftablesSchema<'static>, NftError> {
    nftables::helper::get_current_ruleset()
        .map_err(|e| NftError::Nft(format!("{e:?}")))
}

/// Validate a script without applying it. Works for both full and patch scripts.
pub fn validate_script(content: &str) -> Result<(), NftError> {
    let mut f = NamedTempFile::new()?;
    f.write_all(content.replace("\r\n", "\n").as_bytes())?;
    let out = Command::new("nft").args(["-c", "-f"]).arg(f.path()).output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    tracing::debug!(status = %out.status, stdout = %stdout, stderr = %stderr, "nft validate");
    if out.status.success() {
        Ok(())
    } else {
        let msg = match (stdout.trim().is_empty(), stderr.trim().is_empty()) {
            (false, false) => format!("{}\n{}", stderr.trim(), stdout.trim()),
            (true, _) => stderr.trim().to_string(),
            (_, true) => stdout.trim().to_string(),
        };
        Err(NftError::Nft(msg))
    }
}

/// Apply a full ruleset replacement. Prepends `flush ruleset` if absent.
pub fn apply_full(content: &str) -> Result<(), NftError> {
    let script = if content.trim_start().starts_with("flush ruleset") {
        content.to_string()
    } else {
        format!("flush ruleset\n{content}")
    };
    run_script(&script)
}

/// Apply an incremental patch script.
pub fn apply_patch(content: &str) -> Result<(), NftError> {
    run_script(content)
}

/// Restore a previously saved ruleset text (used for rollback).
pub fn restore(previous_text: &str) -> Result<(), NftError> {
    let script = if previous_text.trim_start().starts_with("flush ruleset") {
        previous_text.to_string()
    } else {
        format!("flush ruleset\n{previous_text}")
    };
    run_script(&script)
}

/// Read the saved nftables config file.
pub fn read_saved_config(path: &str) -> Result<String, NftError> {
    std::fs::read_to_string(path).map_err(NftError::Io)
}

/// Write content to the saved config, backing up the previous file first.
pub fn write_saved_config(path: &str, content: &str, backup_dir: &str) -> Result<(), NftError> {
    let config_path = std::path::Path::new(path);
    if config_path.exists() {
        std::fs::create_dir_all(backup_dir)?;
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let stamp = unix_to_stamp(secs);
        let backup = std::path::Path::new(backup_dir).join(format!("nftables.conf.{stamp}"));
        std::fs::copy(config_path, backup)?;
    }
    std::fs::write(config_path, content.replace("\r\n", "\n")).map_err(NftError::Io)
}

fn unix_to_stamp(secs: u64) -> String {
    let (h, m, s) = (secs % 86400 / 3600, secs % 3600 / 60, secs % 60);
    let mut year = 1970u64;
    let mut rem = secs / 86400;
    loop {
        let dy = if leap(year) { 366 } else { 365 };
        if rem < dy { break; }
        rem -= dy;
        year += 1;
    }
    let mdays = [31u64, if leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    for dm in mdays {
        if rem < dm { break; }
        rem -= dm;
        month += 1;
    }
    format!("{year:04}-{month:02}-{:02}T{h:02}-{m:02}-{s:02}", rem + 1)
}

fn leap(y: u64) -> bool { (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 }

/// Build an incremental patch from a saved config.
/// For each table: add (idempotent), flush, redefine. Prepend all defines.
/// Tables not mentioned in the saved config are left untouched in the running ruleset.
pub fn build_saved_config_patch(content: &str) -> String {
    let mut script = String::new();

    // All define lines first.
    for line in content.lines() {
        if line.trim().starts_with("define ") {
            script.push_str(line);
            script.push('\n');
        }
    }
    if !script.is_empty() {
        script.push('\n');
    }

    // Extract and emit each table block.
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.starts_with('#') { i += 1; continue; }

        if let Some(rest) = trimmed.strip_prefix("table ") {
            let tokens: Vec<&str> = rest.split_whitespace().collect();
            if tokens.len() >= 2 {
                let family = tokens[0];
                let name = tokens[1].trim_end_matches('{').trim();
                let start = i;
                let mut depth = 0i32;
                let mut end = i;
                'blk: while end < lines.len() {
                    for ch in lines[end].chars() {
                        match ch {
                            '{' => depth += 1,
                            '}' => { depth -= 1; if depth == 0 { break 'blk; } }
                            _ => {}
                        }
                    }
                    end += 1;
                }
                let block = lines[start..=end.min(lines.len() - 1)].join("\n");
                script.push_str(&format!("add table {family} {name}\n"));
                script.push_str(&format!("flush table {family} {name}\n"));
                script.push_str(&block);
                script.push_str("\n\n");
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }

    script
}

/// Network interfaces from /sys/class/net, sorted.
pub fn get_interfaces() -> Vec<String> {
    let mut ifaces: Vec<String> = std::fs::read_dir("/sys/class/net")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
              .map(|e| e.file_name().to_string_lossy().into_owned())
              .collect()
        })
        .unwrap_or_default();
    ifaces.sort();
    ifaces
}

/// Extract `define NAME = VALUE` declarations from ruleset text.
pub fn parse_defines(ruleset: &str) -> Vec<(String, String)> {
    ruleset
        .lines()
        .filter_map(|line| {
            let t = line.trim();
            let rest = t.strip_prefix("define ")?;
            let (name, val) = rest.split_once(" = ")?;
            Some((name.trim().to_string(), val.trim().to_string()))
        })
        .collect()
}

/// Extract set names from ruleset text.
pub fn parse_sets(ruleset: &str) -> Vec<String> {
    ruleset
        .lines()
        .filter_map(|line| {
            let t = line.trim();
            let rest = t.strip_prefix("set ")?;
            let name = rest.trim_end_matches(|c: char| c == '{' || c.is_ascii_whitespace());
            if name.is_empty() { None } else { Some(name.to_string()) }
        })
        .collect()
}

fn run_script(content: &str) -> Result<(), NftError> {
    let mut f = NamedTempFile::new()?;
    f.write_all(content.replace("\r\n", "\n").as_bytes())?;
    let out = Command::new("nft").arg("-f").arg(f.path()).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(NftError::Nft(String::from_utf8_lossy(&out.stderr).into_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
table inet filter { # handle 1
\tchain input { # handle 1
\t\ttype filter hook input priority 0; policy drop;
\t\tct state established,related accept # handle 3
\t\tiif lo accept # handle 4
\t\ttcp dport 22 accept # handle 5
\t\tdrop # handle 6
\t} # handle 1

\tchain forward { # handle 2
\t\tdrop # handle 7
\t} # handle 2
} # handle 1
table ip nat { # handle 2
\tchain postrouting { # handle 1
\t\tmasquerade # handle 2
\t} # handle 1
} # handle 2";

    #[test]
    fn test_parse_ruleset_handles_maps_rules() {
        let map = parse_ruleset_handles(SAMPLE);
        // line 3 = ct state...
        let r = map.get(&3).expect("line 3 should be a rule");
        assert_eq!(r.table_family, "inet");
        assert_eq!(r.table_name, "filter");
        assert_eq!(r.chain_name, "input");
        assert_eq!(r.handle, 3);

        // line 10 = drop (forward chain)
        let r2 = map.get(&10).expect("line 10 should be a rule");
        assert_eq!(r2.chain_name, "forward");
        assert_eq!(r2.handle, 7);

        // nat table — masquerade is line 15
        let r3 = map.get(&15).expect("line 15 should be a rule");
        assert_eq!(r3.table_family, "ip");
        assert_eq!(r3.table_name, "nat");
        assert_eq!(r3.handle, 2);
    }

    #[test]
    fn test_parse_skips_declarations_and_closing_braces() {
        let map = parse_ruleset_handles(SAMPLE);
        // line 2 = type filter hook ... (chain declaration) — must not appear
        assert!(!map.contains_key(&2), "chain type declaration should not be a rule");
        // table/chain header lines
        assert!(!map.contains_key(&0), "table line should not be a rule");
        assert!(!map.contains_key(&1), "chain line should not be a rule");
    }

    #[test]
    fn test_extract_handle() {
        assert_eq!(extract_handle("\t\ttcp dport 22 accept # handle 5"), Some(5));
        assert_eq!(extract_handle("table inet filter { # handle 1"), Some(1));
        assert_eq!(extract_handle("\t\ttype filter hook input priority 0; policy drop;"), None);
        assert_eq!(extract_handle(""), None);
    }
}
