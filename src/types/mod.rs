pub mod chuni;
pub mod tachi;

use chrono::{FixedOffset, NaiveDateTime, TimeZone};
use num_enum::TryFromPrimitiveError;
use snafu::{ResultExt, Snafu};

use self::{
    chuni::{upsert::UserPlaylog, UpsertUserAllRequest},
    tachi::batch_manual::{
        class::ClassEmblem,
        score::{Difficulty, Judgements, Lamp, MatchType, OptionalMetrics},
        BatchManualClasses, BatchManualImport, BatchManualScore,
    },
};

#[derive(Debug, Snafu)]
pub enum ScoreConversionError {
    #[snafu(display("Unknown difficulty index."))]
    InvalidDifficulty {
        source: TryFromPrimitiveError<Difficulty>,
    },

    #[snafu(display("Invalid play date."))]
    InvalidPlayDate { source: chrono::format::ParseError },
}

impl UserPlaylog {
    pub fn to_batch_manual(
        &self,
        major_version: u16,
        fail_over_lamp: bool,
    ) -> Result<BatchManualScore, ScoreConversionError> {
        let lamp = if !self.is_clear && fail_over_lamp {
            Lamp::Failed
        } else if self.is_all_justice {
            if self.judge_justice + self.judge_attack + self.judge_guilty == 0 {
                Lamp::AllJusticeCritical
            } else {
                Lamp::AllJustice
            }
        } else if self.is_full_combo {
            Lamp::FullCombo
        } else if self.is_clear {
            Lamp::Clear
        } else {
            Lamp::Failed
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

        let datetime = NaiveDateTime::parse_from_str(&self.user_play_date, "%Y-%m-%d %H:%M:%S")
            .context(InvalidPlayDateSnafu)?;
        let jst_offset = FixedOffset::east_opt(9 * 3600).expect("chrono should parse JST timezone");
        let jst_time = jst_offset.from_local_datetime(&datetime).unwrap();

        Ok(BatchManualScore {
            score: self.score,
            lamp,
            match_type: MatchType::InGameId,
            identifier: self.music_id.clone(),
            difficulty,
            time_achieved: Some(jst_time.timestamp_millis() as u128),
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
        fail_over_lamp: bool,
    ) -> BatchManualImport;
}

impl ToBatchManual for UpsertUserAllRequest {
    fn to_batch_manual(
        &self,
        major_version: u16,
        export_class: bool,
        fail_over_lamp: bool,
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
                .map(|b| ClassEmblem::try_from(b).ok())
                .flatten();

            Some(BatchManualClasses { dan, emblem })
        } else {
            None
        };

        let scores = self
            .upsert_user_all
            .user_playlog_list
            .iter()
            .filter_map(|p| {
                let conv = p.to_batch_manual(major_version, fail_over_lamp);

                if conv
                    .as_ref()
                    .is_ok_and(|s| s.difficulty != Difficulty::WorldsEnd)
                {
                    conv.ok()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        BatchManualImport {
            classes,
            scores,
            ..Default::default()
        }
    }
}
