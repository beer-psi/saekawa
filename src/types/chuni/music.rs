use serde::{Deserialize, Serialize};
use serde_aux::prelude::*;

use super::deserialize_bool;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserMusicResponse {
    pub user_id: String,
    pub length: u32,
    pub user_music_list: Vec<UserMusicItem>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserMusicItem {
    pub length: u32,
    pub user_music_detail_list: Vec<UserMusicDetail>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserMusicDetail {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub music_id: u32,

    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub level: u32,

    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub score_max: u32,

    #[serde(deserialize_with = "deserialize_bool")]
    pub is_all_justice: bool,

    #[serde(deserialize_with = "deserialize_bool")]
    pub is_full_combo: bool,

    #[serde(deserialize_with = "deserialize_bool")]
    pub is_success: bool,
}
