use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchManualMeta {
    pub game: String,
    pub playtype: String,
    pub service: String,
}

impl Default for BatchManualMeta {
    fn default() -> Self {
        Self {
            game: "chunithm".to_string(),
            playtype: "Single".to_string(),
            service: "Saekawa".to_string(),
        }
    }
}
