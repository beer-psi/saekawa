pub mod class;
pub mod meta;
pub mod score;

use serde::{Deserialize, Serialize};

pub use self::{class::BatchManualClasses, meta::BatchManualMeta, score::BatchManualScore};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BatchManualImport {
    pub meta: BatchManualMeta,
    pub scores: Vec<BatchManualScore>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub classes: Option<BatchManualClasses>,
}
