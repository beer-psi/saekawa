use serde::{Deserialize, Serialize};

use super::{api::TachiApiPermission, documents::ImportDocument};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerStatus {
    pub whoami: Option<u32>,
    pub permissions: Vec<TachiApiPermission>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportDeferred {
    pub url: String,

    #[serde(rename = "importID")]
    pub import_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ImportResponse {
    Deferred(ImportDeferred),
    Completed(ImportDocument),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImportProgress {
    NotStarted(u32),
    Ongoing { description: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "importStatus")]
pub enum ImportPollStatus {
    #[serde(rename = "ongoing")]
    Ongoing { progress: ImportProgress },

    #[serde(rename = "completed")]
    Completed { import: ImportDocument },
}
