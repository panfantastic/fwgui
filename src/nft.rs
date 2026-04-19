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
