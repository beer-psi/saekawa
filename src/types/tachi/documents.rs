use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SessionType {
    Appended,
    Created,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportErrContent {
    #[serde(rename = "type")]
    pub error_type: String,

    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfoReturn {
    #[serde(rename = "type")]
    pub session_type: SessionType,

    #[serde(rename = "sessionID")]
    pub session_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportDocument {
    #[serde(rename = "scoreIDs")]
    pub score_ids: Vec<String>,

    pub errors: Vec<ImportErrContent>,

    #[serde(rename = "createdSessions")]
    pub created_sessions: Vec<SessionInfoReturn>,
}
