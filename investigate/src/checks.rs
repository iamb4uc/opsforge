use crate::case::CoverageState;
use serde::{Deserialize, Serialize};

#[cfg(unix)]
mod linux;
#[cfg(unix)]
pub(crate) use linux::collect;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Finding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub host: String,
    pub category: String,
    pub evidence: String,
    pub recommendation: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct CheckResult {
    pub tool: String,
    pub state: CoverageState,
    pub started_at: String,
    pub finished_at: String,
    pub exit_code: Option<i32>,
    pub detail: String,
    pub evidence: String,
    pub findings: Vec<Finding>,
}
