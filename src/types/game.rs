use serde::{de, Deserialize, Serialize};
use serde_aux::prelude::*;

fn deserialize_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: &str = de::Deserialize::deserialize(deserializer)?;

    match s {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(de::Error::unknown_variant(s, &["true", "false"])),
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserData {
    pub access_code: String,

    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub class_emblem_base: u32,

    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub class_emblem_medal: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPlaylog {
    // This decides what `level` indices mean.
    // rom version 1.xx.yy: 0->4 for BASIC/ADVANCED/EXPERT/MASTER/WORLD'S END
    // rom version 2.xx.yy: 0->5 for BASIC/ADVANCED/EXPERT/MASTER/ULTIMA/WORLD'S END
    pub rom_version: String,

    pub music_id: String,

    // This is in UTC+9
    pub user_play_date: String,

    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub level: u32,

    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub score: u32,

    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub max_combo: u32,

    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub judge_guilty: u32,

    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub judge_attack: u32,

    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub judge_justice: u32,

    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub judge_critical: u32,
    // Only introduced in CHUNITHM NEW, thus needing a default value.
    #[serde(
        default = "default_judge_heaven",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub judge_heaven: u32,

    #[serde(deserialize_with = "deserialize_bool")]
    pub is_all_justice: bool,

    #[serde(deserialize_with = "deserialize_bool")]
    pub is_full_combo: bool,

    #[serde(deserialize_with = "deserialize_bool")]
    pub is_clear: bool,
}

fn default_judge_heaven<'a>() -> u32 {
    0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertUserAllBody {
    pub user_data: Vec<UserData>,
    pub user_playlog_list: Vec<UserPlaylog>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertUserAllRequest {
    pub user_id: String,
    pub upsert_user_all: UpsertUserAllBody,
}
