use anyhow::Result;
use chrono::{FixedOffset, NaiveDateTime, TimeZone};
use num_enum::TryFromPrimitive;
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use super::game::{UpsertUserAllRequest, UserMusicDetail, UserMusicResponse, UserPlaylog};

#[derive(Debug, Clone)]
pub enum TachiResponse<T> {
    Ok(TachiSuccessResponse<T>),
    Err(TachiErrorResponse),
}

impl<'de, T> Deserialize<'de> for TachiResponse<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<TachiResponse<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = Map::deserialize(deserializer)?;

        let success = map
            .remove("success")
            .ok_or_else(|| de::Error::missing_field("success"))
            .map(Deserialize::deserialize)?
            .map_err(de::Error::custom)?;
        let rest = Value::Object(map);

        if success {
            TachiSuccessResponse::deserialize(rest)
                .map(TachiResponse::Ok)
                .map_err(de::Error::custom)
        } else {
            TachiErrorResponse::deserialize(rest)
                .map(TachiResponse::Err)
                .map_err(de::Error::custom)
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TachiSuccessResponse<T> {
    pub description: String,
    pub body: T,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TachiErrorResponse {
    pub description: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusCheck {
    pub permissions: Vec<String>,
    pub whoami: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ImportResponse {
    Queued {
        url: String,

        #[serde(rename = "importID")]
        import_id: String,
    },
    Finished(ImportDocument),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportDocument {
    #[serde(rename = "scoreIDs")]
    pub score_ids: Vec<String>,

    pub errors: Vec<ImportErrContent>,

    #[serde(rename = "createdSessions")]
    pub created_sessions: Vec<SessionInfoReturn>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportErrContent {
    #[serde(rename = "type")]
    pub error_type: String,

    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionInfoReturn {
    #[serde(rename = "type")]
    pub session_type: String,

    #[serde(rename = "sessionID")]
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "importStatus")]
pub enum ImportPollStatus {
    #[serde(rename = "ongoing")]
    Ongoing { progress: ImportProgress },

    #[serde(rename = "completed")]
    Completed { import: ImportDocument },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportProgress {
    pub description: String,
    pub value: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Import {
    pub meta: ImportMeta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classes: Option<ImportClasses>,
    pub scores: Vec<ImportScore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportMeta {
    pub game: String,
    pub playtype: String,
    pub service: String,
}

impl Default for ImportMeta {
    fn default() -> Self {
        Self {
            game: "chunithm".to_string(),
            playtype: "Single".to_string(),
            service: "Saekawa".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportClasses {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportScore {
    pub score: u32,
    pub lamp: TachiLamp,
    pub match_type: String,
    pub identifier: String,
    pub difficulty: Difficulty,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_achieved: Option<u128>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub judgements: Option<Judgements>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<OptionalMetrics>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, TryFromPrimitive)]
#[repr(u32)]
pub enum TachiLamp {
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

impl ImportScore {
    pub fn try_from_playlog(
        p: &UserPlaylog,
        major_version: u16,
        fail_over_lamp: bool,
    ) -> Result<ImportScore> {
        let lamp = if !p.is_clear && fail_over_lamp {
            TachiLamp::Failed
        } else if p.is_all_justice {
            if p.judge_justice + p.judge_attack + p.judge_guilty == 0 {
                TachiLamp::AllJusticeCritical
            } else {
                TachiLamp::AllJustice
            }
        } else if p.is_full_combo {
            TachiLamp::FullCombo
        } else if p.is_clear {
            TachiLamp::Clear
        } else {
            TachiLamp::Failed
        };

        let judgements = Judgements {
            jcrit: p.judge_heaven + p.judge_critical,
            justice: p.judge_justice,
            attack: p.judge_attack,
            miss: p.judge_guilty,
        };

        let difficulty = if major_version == 1 && p.level == 4 {
            Difficulty::WorldsEnd
        } else {
            Difficulty::try_from(p.level)?
        };

        let datetime = NaiveDateTime::parse_from_str(&p.user_play_date, "%Y-%m-%d %H:%M:%S")?;
        let jst_offset =
            FixedOffset::east_opt(9 * 3600).expect("chrono should be able to parse JST timezone");
        let jst_time = jst_offset.from_local_datetime(&datetime).unwrap();

        Ok(ImportScore {
            score: p.score,
            lamp,
            match_type: "inGameID".to_string(),
            identifier: p.music_id.clone(),
            difficulty,
            time_achieved: Some(jst_time.timestamp_millis() as u128),
            judgements: Some(judgements),
            optional: Some(OptionalMetrics {
                max_combo: p.max_combo,
            }),
        })
    }

    fn try_from_music_detail(
        d: &UserMusicDetail,
        major_version: u16,
        fail_over_lamp: bool,
    ) -> Result<ImportScore> {
        let lamp = if !d.is_success && fail_over_lamp {
            TachiLamp::Failed
        } else if d.is_all_justice {
            TachiLamp::AllJustice
        } else if d.is_full_combo {
            TachiLamp::FullCombo
        } else if d.is_success {
            TachiLamp::Clear
        } else {
            TachiLamp::Failed
        };

        let difficulty = if major_version == 1 && d.level == 4 {
            Difficulty::WorldsEnd
        } else {
            Difficulty::try_from(d.level)?
        };

        Ok(ImportScore {
            score: d.score_max,
            lamp,
            match_type: "inGameID".to_string(),
            identifier: d.music_id.to_string(),
            difficulty,
            time_achieved: None,
            judgements: None,
            optional: None,
        })
    }
}

pub trait ToTachiImport {
    fn displayed_id(&self) -> &str;
    fn displayed_id_type(&self) -> &str;
    fn to_tachi_import(
        &self,
        major_version: u16,
        export_class: bool,
        fail_over_lamp: bool,
    ) -> Import;
}

impl ToTachiImport for UserMusicResponse {
    fn displayed_id(&self) -> &str {
        &self.user_id
    }

    fn displayed_id_type(&self) -> &str {
        "user ID"
    }

    fn to_tachi_import(&self, major_version: u16, _: bool, fail_over_lamp: bool) -> Import {
        let scores = self
            .user_music_list
            .iter()
            .flat_map(|item| {
                item.user_music_detail_list.iter().filter_map(|d| {
                    let result =
                        ImportScore::try_from_music_detail(d, major_version, fail_over_lamp);
                    if result
                        .as_ref()
                        .is_ok_and(|v| v.difficulty != Difficulty::WorldsEnd)
                    {
                        result.ok()
                    } else {
                        None
                    }
                })
            })
            .collect::<Vec<_>>();

        Import {
            scores,
            ..Default::default()
        }
    }
}

impl ToTachiImport for UpsertUserAllRequest {
    fn displayed_id(&self) -> &str {
        let user_data = &self.upsert_user_all.user_data[0];

        &user_data.access_code
    }

    fn displayed_id_type(&self) -> &str {
        "access code"
    }

    fn to_tachi_import(
        &self,
        major_version: u16,
        export_class: bool,
        fail_over_lamp: bool,
    ) -> Import {
        let user_data = &self.upsert_user_all.user_data[0];

        let classes = if export_class {
            Some(ImportClasses {
                dan: ClassEmblem::try_from(user_data.class_emblem_medal).ok(),
                emblem: ClassEmblem::try_from(user_data.class_emblem_base).ok(),
            })
        } else {
            None
        };

        let scores = self
            .upsert_user_all
            .user_playlog_list
            .iter()
            .filter_map(|playlog| {
                let result = ImportScore::try_from_playlog(playlog, major_version, fail_over_lamp);
                if result
                    .as_ref()
                    .is_ok_and(|v| v.difficulty != Difficulty::WorldsEnd)
                {
                    result.ok()
                } else {
                    None
                }
            })
            .collect::<Vec<ImportScore>>();

        Import {
            classes,
            scores,
            ..Default::default()
        }
    }
}
