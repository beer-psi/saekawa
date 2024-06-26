use serde::{Deserialize, Serialize};

use super::defaults::*;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OldSaekawaConfig {
    pub general: OldGeneralConfig,
    pub cards: OldCardsConfig,
    pub tachi: OldTachiConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OldGeneralConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default = "default_true")]
    pub export_class: bool,

    #[serde(default = "default_false")]
    pub export_pbs: bool,

    #[serde(default = "default_false")]
    pub fail_over_lamp: bool,

    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OldCardsConfig {
    #[serde(default)]
    pub whitelist: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OldTachiConfig {
    pub base_url: String,
    pub status: String,
    pub import: String,
    pub api_key: String,
}
