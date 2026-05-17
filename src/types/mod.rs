pub mod chuni;
pub mod tachi;

use log::warn;
use num_enum::TryFromPrimitiveError;
use snafu::{ResultExt, Snafu};
use tachi::batch_manual::score::NoteLamp;

use self::{
    chuni::{upsert::UserPlaylog, UpsertUserAllRequest},
    tachi::batch_manual::{
        class::ClassEmblem,
        score::{ClearLamp, Difficulty, Judgements, MatchType, OptionalMetrics},
        BatchManualClasses, BatchManualImport, BatchManualScore,
    },
};

// they forgot about cts skill for sun for some reason, funny
const CATASTROPHY_SKILL_IDS: [u32; 3] = [100009, 102009, 103007];
const ABSOLUTE_SKILL_IDS: [u32; 4] = [100008, 101008, 102008, 103006];
const BRAVE_SKILL_IDS: [u32; 4] = [100007, 101007, 102007, 103005];
const HARD_SKILL_IDS: [u32; 11] = [
    100005, 100006, 101004, 101005, 101006, 102004, 102005, 102006, 103002, 103003, 103004,
];

#[derive(Debug, Snafu)]
pub enum ScoreConversionError {
    #[snafu(display("Unknown difficulty index."))]
    InvalidDifficulty {
        source: TryFromPrimitiveError<Difficulty>,
    },
}

impl UserPlaylog {
    pub fn to_batch_manual(
        &self,
        major_version: u16,
        replace_tz: Option<jiff::tz::TimeZone>,
    ) -> Result<BatchManualScore, ScoreConversionError> {
        let note_lamp = if self.is_all_justice
            && self.judge_justice + self.judge_attack + self.judge_guilty == 0
        {
            NoteLamp::AllJusticeCritical
        } else if self.is_all_justice {
            NoteLamp::AllJustice
        } else if self.is_full_combo {
            NoteLamp::FullCombo
        } else {
            NoteLamp::None
        };

        let clear_lamp = if !self.is_clear {
            ClearLamp::Failed
        } else if CATASTROPHY_SKILL_IDS.contains(&self.skill_id) {
            ClearLamp::Catastrophy
        } else if ABSOLUTE_SKILL_IDS.contains(&self.skill_id) {
            ClearLamp::Absolute
        } else if BRAVE_SKILL_IDS.contains(&self.skill_id) {
            ClearLamp::Brave
        } else if HARD_SKILL_IDS.contains(&self.skill_id) {
            ClearLamp::Hard
        } else {
            ClearLamp::Clear
        };

        let judgements = Judgements {
            jcrit: self.judge_heaven + self.judge_critical,
            justice: self.judge_justice,
            attack: self.judge_attack,
            miss: self.judge_guilty,
        };

        let difficulty = if major_version == 1 && self.level == 4 {
            Difficulty::WorldsEnd
        } else {
            Difficulty::try_from(self.level).context(InvalidDifficultySnafu)?
        };
        let time_achieved = if let Some(replace_tz) = replace_tz {
            match self.user_play_date.datetime().to_zoned(replace_tz) {
                Ok(user_play_date) => Some(user_play_date.timestamp().as_millisecond()),
                Err(e) => {
                    warn!("Cannot replace the timestamp's time zone: {e:?}");
                    None
                }
            }
        } else {
            Some(self.user_play_date.timestamp().as_millisecond())
        };

        Ok(BatchManualScore {
            score: self.score,
            note_lamp,
            clear_lamp,
            match_type: if difficulty == Difficulty::WorldsEnd {
                MatchType::GcmInGameIdSpecialChart
            } else {
                MatchType::InGameId
            },
            identifier: self.music_id.clone(),
            difficulty: if difficulty == Difficulty::WorldsEnd {
                None
            } else {
                Some(difficulty)
            },
            time_achieved,
            judgements: Some(judgements),
            optional: Some(OptionalMetrics {
                max_combo: self.max_combo,
            }),
        })
    }
}

pub trait ToBatchManual {
    fn to_batch_manual(
        &self,
        major_version: u16,
        export_class: bool,
        replace_tz: Option<jiff::tz::TimeZone>,
    ) -> BatchManualImport;
}

impl ToBatchManual for UpsertUserAllRequest {
    fn to_batch_manual(
        &self,
        major_version: u16,
        export_class: bool,
        replace_tz: Option<jiff::tz::TimeZone>,
    ) -> BatchManualImport {
        let user_data = &self.upsert_user_all.user_data[0];

        let classes = if export_class {
            let dan = if let Some(medal) = user_data.class_emblem_medal {
                ClassEmblem::try_from(medal).ok()
            } else if let Some(user_data_ex) = &self.upsert_user_all.user_data_ex {
                ClassEmblem::try_from(user_data_ex[0].medal).ok()
            } else {
                None
            };
            let emblem = user_data
                .class_emblem_base
                .and_then(|b| ClassEmblem::try_from(b).ok());

            Some(BatchManualClasses { dan, emblem })
        } else {
            None
        };

        let scores = self
            .upsert_user_all
            .user_playlog_list
            .iter()
            .filter_map(|p| p.to_batch_manual(major_version, replace_tz.clone()).ok())
            .collect::<Vec<_>>();

        BatchManualImport {
            classes,
            scores,
            ..Default::default()
        }
    }
}
