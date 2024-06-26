use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BatchManualClasses {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dan: Option<ClassEmblem>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub emblem: Option<ClassEmblem>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, TryFromPrimitive)]
#[repr(u32)]
pub enum ClassEmblem {
    #[serde(rename = "DAN_I")]
    First = 1,

    #[serde(rename = "DAN_II")]
    Second = 2,

    #[serde(rename = "DAN_III")]
    Third = 3,

    #[serde(rename = "DAN_IV")]
    Fourth = 4,

    #[serde(rename = "DAN_V")]
    Fifth = 5,

    #[serde(rename = "DAN_INFINITE")]
    Infinite = 6,
}
