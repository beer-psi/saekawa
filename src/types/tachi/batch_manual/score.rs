use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchManualScore {
    pub match_type: MatchType,
    pub identifier: String,
    pub difficulty: Difficulty,
    pub score: u32,
    pub lamp: Lamp,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub judgements: Option<Judgements>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_achieved: Option<u128>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<OptionalMetrics>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, TryFromPrimitive)]
#[repr(u32)]
pub enum Lamp {
    #[serde(rename = "FAILED")]
    Failed = 0,

    #[serde(rename = "CLEAR")]
    Clear = 1,

    #[serde(rename = "FULL COMBO")]
    FullCombo = 2,

    #[serde(rename = "ALL JUSTICE")]
    AllJustice = 3,

    #[serde(rename = "ALL JUSTICE CRITICAL")]
    AllJusticeCritical = 4,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, TryFromPrimitive)]
#[repr(u32)]
pub enum Difficulty {
    #[serde(rename = "BASIC")]
    Basic = 0,

    #[serde(rename = "ADVANCED")]
    Advanced = 1,

    #[serde(rename = "EXPERT")]
    Expert = 2,

    #[serde(rename = "MASTER")]
    Master = 3,

    #[serde(rename = "ULTIMA")]
    Ultima = 4,

    #[serde(rename = "WORLD'S END")]
    WorldsEnd = 5,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MatchType {
    #[serde(rename = "bmsChartHash")]
    BmsChartHash,

    #[serde(rename = "itgChartHash")]
    ItgChartHash,

    #[serde(rename = "popnChartHash")]
    PopnChartHash,

    #[serde(rename = "uscChartHash")]
    UscChartHash,

    #[serde(rename = "inGameID")]
    InGameId,

    #[serde(rename = "inGameStrID")]
    InGameStrId,

    #[serde(rename = "sdvxInGameID")]
    SdvxInGameId,

    #[serde(rename = "songTitle")]
    SongTitle,

    #[serde(rename = "tachiSongID")]
    TachiSongId,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Judgements {
    pub jcrit: u32,
    pub justice: u32,
    pub attack: u32,
    pub miss: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OptionalMetrics {
    pub max_combo: u32,
}
