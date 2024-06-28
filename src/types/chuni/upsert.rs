use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_aux::prelude::*;

use super::{deserialize_bool, serde_user_play_date};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertUserAllRequest {
    pub user_id: String,
    pub upsert_user_all: UpsertUserAllBody,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertUserAllBody {
    pub user_data: Vec<UserData>,
    pub user_data_ex: Option<Vec<UserDataEx>>,
    pub user_playlog_list: Vec<UserPlaylog>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserData {
    pub access_code: String,

    #[serde(
        default = "default_class_emblem",
        deserialize_with = "deserialize_option_number_from_string"
    )]
    pub class_emblem_base: Option<u32>,

    #[serde(
        default = "default_class_emblem",
        deserialize_with = "deserialize_option_number_from_string"
    )]
    pub class_emblem_medal: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDataEx {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub medal: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPlaylog {
    /// This decides what `level` indices mean.
    /// rom version 1.xx.yy: 0->4 for BASIC/ADVANCED/EXPERT/MASTER/WORLD'S END
    /// rom version 2.xx.yy: 0->5 for BASIC/ADVANCED/EXPERT/MASTER/ULTIMA/WORLD'S END
    pub rom_version: String,

    pub music_id: String,

    /// The date and time the player set this score with, in the local time
    /// perceived by the game. On most setups this will be UTC+9.
    #[serde(with = "serde_user_play_date")]
    pub user_play_date: NaiveDateTime,

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

    /// In CHUNITHM SUN+ and beyond this is actually an integer, with different
    /// indexes for different clear lamps, ranging from a normal CLEAR to a CATASTROPHY
    /// (similar to EX HARD CLEAR). To keep things simple it's all smushed to a boolean,
    /// since Tachi doesn't implement those clear lamps.
    #[serde(deserialize_with = "deserialize_bool")]
    pub is_clear: bool,
}

fn default_judge_heaven() -> u32 {
    0
}

fn default_class_emblem() -> Option<u32> {
    None
}
