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
