use std::mem::offset_of;

use crate::types::stl::StdString;

#[repr(C)]
pub struct TimingCount {
    pub on_time: i32,
    pub fast: i32,
    pub late: i32,
}

#[repr(C)]
pub struct TimingCounts {
    pub miss: TimingCount,
    pub attack: TimingCount,
    pub justice: TimingCount,
    pub justice_critical: TimingCount,
    pub justice_heaven: TimingCount,
}

#[repr(C)]
pub struct JudgeStatsBlock {
    pub note_count: i32,
    pub kind_value: [i32; 5],
    pub kind_max_score: [i32; 5],
    pub live_kind_count: [i32; 5],
    pub kind_product: [i32; 5],
    pub current_rate: i32,
    pub timing_counts: TimingCounts,
}

#[repr(C)]
pub struct JudgeStats {
    pub initialized: bool,
    pad1: [u8; 3],
    pub tap: JudgeStatsBlock,
    pub hold: JudgeStatsBlock,
    pub slide: JudgeStatsBlock,
    pub air: JudgeStatsBlock,
    pub flick: JudgeStatsBlock,
    pub denominators: [i32; 5],
    pub score: i32,
    pub score_lost: i32,
    pub combo: i32,
    pub max_combo: i32,
}

#[repr(C)]
pub struct TrackResult {
    pub judge_stats: JudgeStats,
    pad2: [u8; 0x4D4],
    pub max_chain: i32,
    pad3: [u8; 0x90],
    pub clear_flags: [u8; 3],
}

#[repr(C)]
pub struct JudgeContext {}

#[repr(C)]
pub struct PlayRecord {
    pub place_id: i32,
    pub user_play_date: i32, // unix seconds
    pub play_date: i32,
    pub track: u8,
    pad0: [u8; 3],
    pub music_id: i32,
    pub level: u8,
    pub custom_id: u8,
    pad1: [u8; 2],
    pub play_kind: u16,
    pad2: [u8; 2],
    pub opponents: [u32; 3],
    pub score: i32,
    pub rank: u16,
    pad3: [u8; 2],
    pub max_combo: i32,
    pub max_chain: i32,
    pub judge_guilty: i32,
    pub judge_attack: i32,
    pub judge_justice: i32,
    pub judge_critical: i32,
    pub judge_heaven: i32,
    pub rate_tap: i32,
    pub rate_hold: i32,
    pub rate_slide: i32,
    pub rate_air: i32,
    pub rate_flick: i32,
    pub is_new_record: bool,
    pub is_clear: bool,
    pub is_full_combo: bool,
    pad4: u8,
    pub full_chain_kind: u16,
    pad5: [u8; 2],
    pub is_all_justice: bool,
    pub is_continue: bool,
    pub is_free_to_play: bool,
    pad6: u8,
    pub player_rating: i32,
    pub character_id: i32,
    pub chara_illust_id: i32,
    pub skill_id: i32,
    pub skill_level: i32,
    pub skill_effect: i32,
    pub event_id: i32,
    pub strings: [StdString; 2],
    pub net_extra: [i32; 3],
    pub month_point: i32,
    pub event_point: i32,
    pub common_id: i32,
    pub ticket_id: i32,
}

const _: () = assert!(offset_of!(PlayRecord, score) == 0x28);
