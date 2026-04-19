use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;
use tokio::sync::oneshot;

use crate::nft::RuleHandle;

pub struct Config {
    pub port: u16,
    pub rollback_secs: u64,
    pub saved_config_path: String,
    pub backup_dir: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            port: std::env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3000),
            rollback_secs: std::env::var("ROLLBACK_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            saved_config_path: std::env::var("NFT_CONFIG_PATH")
                .unwrap_or_else(|_| "/etc/nftables.conf".to_string()),
            backup_dir: std::env::var("NFT_BACKUP_DIR")
                .unwrap_or_else(|_| "/etc/nftables.bak".to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ChangeMode {
    Full,
    Patch,
}

impl std::fmt::Display for ChangeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeMode::Full => write!(f, "Full replacement"),
            ChangeMode::Patch => write!(f, "Patch (incremental)"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct StagedChange {
    pub mode: ChangeMode,
    pub content: String,
    /// Original saved config text to write to disk when the promotion is acknowledged.
    /// None when staging from running config mode.
    pub saved_config: Option<String>,
}

pub enum FwState {
    Idle,
    Staged(StagedChange),
    Promoting {
        change: StagedChange,
        previous_text: String,
        deadline: Instant,
        cancel_tx: oneshot::Sender<()>,
    },
}

pub struct ActiveBreakpoint {
    pub rule: RuleHandle,
    pub log_handle: u64,
}

pub struct AppState {
    pub fw: Mutex<FwState>,
    pub config: Config,
    /// Active breakpoints keyed by 0-based line number in the annotated ruleset.
    pub breakpoints: Mutex<HashMap<usize, ActiveBreakpoint>>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            fw: Mutex::new(FwState::Idle),
            config,
            breakpoints: Mutex::new(HashMap::new()),
        }
    }
}
