use anyhow::{anyhow, Result};
use chrono::{FixedOffset, NaiveDateTime, TimeZone};
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use super::game::UserPlaylog;

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
    pub difficulty: String,
    pub time_achieved: u128,
    pub judgements: Judgements,
    pub optional: OptionalMetrics,
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
    pub fn try_from_playlog(p: UserPlaylog, fail_over_lamp: bool) -> Result<ImportScore> {
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

        let rom_major_version = p.rom_version.split('.').next().unwrap_or("2");
        let difficulty = match p.level {
            0 => "BASIC",
            1 => "ADVANCED",
            2 => "EXPERT",
            3 => "MASTER",
            4 => if rom_major_version == "2" {
                "ULTIMA"
            } else {
                "WORLD'S END"
            },
            5 => if rom_major_version == "2" {
                "WORLD'S END"
            } else {
                return Err(anyhow!("difficulty index '5' should not be possible on rom_version {rom_major_version}."));
            },
            _ => return Err(anyhow!("unknown difficulty index {level} on major version {rom_major_version}", level=p.level)),
        }.to_string();

        let datetime = NaiveDateTime::parse_from_str(&p.user_play_date, "%Y-%m-%d %H:%M:%S")?;
        let jst_offset =
            FixedOffset::east_opt(9 * 3600).expect("chrono should be able to parse JST timezone");
        let jst_time = jst_offset.from_local_datetime(&datetime).unwrap();

        Ok(ImportScore {
            score: p.score,
            lamp,
            match_type: "inGameID".to_string(),
            identifier: p.music_id,
            difficulty,
            time_achieved: jst_time.timestamp_millis() as u128,
            judgements,
            optional: OptionalMetrics {
                max_combo: p.max_combo,
            },
        })
    }
}
