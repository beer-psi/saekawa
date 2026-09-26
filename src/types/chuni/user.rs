use std::{ffi::c_void, mem::offset_of};

use crate::types::stl::{StdString, StdVector};

#[derive(PartialEq, Eq, Clone, Copy)]
#[repr(i32)]
#[allow(dead_code)]
pub enum GameMode {
    Normal = 0,
    Course = 1,
    NationalMatching = 2,
    UnlockChallenge = 3,
    LinkedVerse = 4,
}

#[repr(C)]
pub struct UserData {
    pub user_id: i64,
    pub user_name: StdString,
    pub user_name_ex: StdString,
    pub access_code: StdString,
    unk50: StdString,
    pub friend_count: i32,
    pub reincarnation_num: i32,
    pub level: i32,
    pub exp: i32,
    pub point: i32,
    unk7c: u32,
    pub total_point: i64,
    pub player_rating: i32,
    unk8c: [u8; 4],
    pub highest_rating: i32,
    unk94: u32,
    pub total_hi_score: i64,
    pub total_basic_high_score: i64,
    pub total_advanced_high_score: i64,
    pub total_expert_high_score: i64,
    pub total_master_high_score: i64,
    pub total_ultima_high_score: i64,
    pub play_count: i32,
    pub ext6: i32,
    pub ext7: i32,
    pub event_watched_date: i32,
    pub total_map_num: i32,
    pub played_tutorial_bit: i32,
    pub first_tutorial_cancel_num: u8,
    pub master_tutorial_cancel_num: u8,
    unke2: [u8; 6],
    pub compatible_cm_version: StdString,
    pub medal: i32,
    pub class_emblem_base: i32,
    pub class_emblem_medal: i32,
    pub stocked_grid_count: i32,
    pub ex_map_loop_count: i32,
    pub net_battle_play_count: i32,
    pub net_battle_win_count: i32,
    pub net_battle_lose_count: i32,
    pub net_battle_consecutive_win_count: i32,
    pub over_power_point: i32,
    pub over_power_rate: i32,
    pub over_power_lower_rank: i32,
    pub avatar_point: i32,
    pub battle_rank_id: i32,
    pub battle_rank_point: i32,
    pub rank_up_challenge_results: StdVector<c_void>,
    pub elite_rank_point: i32,
    pub net_battle_1st_count: i32,
    pub net_battle_2nd_count: i32,
    pub net_battle_3rd_count: i32,
    pub net_battle_4th_count: i32,
    pub net_battle_correction: i32,
    pub is_net_battle_host: bool,
    unk161: [u8; 3],
    pub net_battle_end_state: i32,
    pub net_battle_err_cnt: i32,
    pub net_battle_host_err_cnt: i32,
    unk170: i32,
    unk174: i32,
    pub battle_reward_status: i32,
    pub battle_reward_index: i32,
    pub battle_reward_count: i32,
    pub ext2: i32,
    pub ext4: i32,
    pub emoney_balance: i32,
    pub emoney_type: i32,
    pub ext1: i32,
    pub ext5: i32,
    unk19c: [u8; 4],
}

const _: () = assert!(offset_of!(UserData, access_code) == 0x38);

#[repr(C)]
pub struct UserDataManager {
    pub vtable: *const c_void,
    pub implementation: *mut UserDataManagerImpl,
}

#[repr(C)]
pub struct UserDataManagerImpl {
    vtable: *const c_void,
    pad1: [u8; 0x28],
    pub mode: GameMode,
}

const _: () = assert!(offset_of!(UserDataManagerImpl, mode) == 0x2C);
