use std::sync::Mutex;
use std::time::Instant;
use tokio::sync::oneshot;

pub struct Config {
    pub port: u16,
    pub rollback_secs: u64,
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

pub struct AppState {
    pub fw: Mutex<FwState>,
    pub config: Config,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            fw: Mutex::new(FwState::Idle),
            config,
        }
    }
}
