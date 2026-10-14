use std::{
    ffi::c_void,
    mem, ptr,
    sync::{
        atomic::{AtomicI32, AtomicU64, Ordering},
        Arc, LazyLock, Mutex, OnceLock,
    },
    thread,
    time::Duration,
};

use log::{debug, error, info};
use retour::static_detour;
use snafu::Snafu;

use crate::{
    helpers::winapi_ext::perf_counter_ns,
    saekawa::CONFIG,
    scanner::{Scanner, ScannerError},
    score_import::execute_score_import,
    types::{
        chuni::{
            record::{JudgeContext, PlayRecord, TrackResult},
            user::{GameMode, UserData, UserDataManager, UserDataManagerImpl},
        },
        stl::StdList,
        tachi::batch_manual::{
            class::ClassEmblem,
            score::{ClearLamp, Difficulty, Judgements, MatchType, NoteLamp, OptionalMetrics},
            BatchManualClasses, BatchManualImport, BatchManualMeta, BatchManualScore,
        },
    },
};

// NOTE: most of these functions aren't really fastcall but touching thiscall is annoying.
// Functionally these calling conventions are the same, fastcall uses ecx, edx, stack
// while thiscall uses ecx, stack.

static_detour! {
    pub static HookPlayMusicStatePlayInitFunc: unsafe extern "fastcall" fn(
        *mut c_void, *mut c_void
    );
    pub static HookPlayMusicStatePlayUpdateFunc: unsafe extern "fastcall" fn(
        *mut c_void, *mut c_void
    );
    pub static HookGetLostScore: unsafe extern "fastcall" fn(
        *const c_void, *mut c_void
    ) -> i32;
    pub static HookGetLifeRemaining: unsafe extern "fastcall" fn(
        *const JudgeContext, *mut c_void
    ) -> i32;
    pub static HookUserDataManagerImplAddPlayRecord: unsafe extern "fastcall" fn(
        *mut UserDataManagerImpl, *mut c_void, i32, *mut c_void, *const JudgeContext, *mut c_void, *mut c_void, u32
    );
}

type SkillIdToClearTypeFn = unsafe extern "fastcall" fn(*const i32, *mut c_void, bool) -> u8;
type UserDataManagerGetUserDataFn =
    unsafe extern "fastcall" fn(*const UserDataManager) -> *const UserData;
type UserDataManagerGetClassEmblemFn = unsafe extern "fastcall" fn(*const UserDataManager) -> i32;
type GetJudgeContextFn = unsafe extern "C" fn() -> *const JudgeContext;
type JudgeContextGetTrackResultFn =
    unsafe extern "fastcall" fn(*const JudgeContext) -> *const TrackResult;
type CountGuiltyJudgeTotalFn =
    unsafe extern "fastcall" fn(*const c_void, *mut c_void, *const u8) -> i32;

static SKILL_ID_TO_CLEAR_TYPE: OnceLock<SkillIdToClearTypeFn> = OnceLock::new();
static USER_DATA_MANAGER_GET_USER_DATA: OnceLock<UserDataManagerGetUserDataFn> = OnceLock::new();
static USER_DATA_MANAGER_GET_CLASS_EMBLEM_BASE: OnceLock<UserDataManagerGetClassEmblemFn> =
    OnceLock::new();
static USER_DATA_MANAGER_GET_CLASS_EMBLEM_MEDAL: OnceLock<UserDataManagerGetClassEmblemFn> =
    OnceLock::new();
static GET_JUDGE_CONTEXT: OnceLock<GetJudgeContextFn> = OnceLock::new();
static JUDGE_CONTEXT_GET_TRACK_RESULT: OnceLock<JudgeContextGetTrackResultFn> = OnceLock::new();
static COUNT_GUILTY_JUDGE_TOTAL: OnceLock<CountGuiltyJudgeTotalFn> = OnceLock::new();

static USER_DATA_MANAGER_IMPL_PLAY_RECORDS_OFFSET: OnceLock<usize> = OnceLock::new();

static GRAPH_LAST_RECORDED: AtomicU64 = AtomicU64::new(0);
static LOST_SCORE: AtomicI32 = AtomicI32::new(0);
static LIFE_REMAINING: AtomicI32 = AtomicI32::new(0);
static SCORE_GRAPH_VALUES: LazyLock<Arc<Mutex<Vec<i32>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(Vec::with_capacity(270))));
static LIFE_GRAPH_VALUES: LazyLock<Arc<Mutex<Vec<i32>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(Vec::with_capacity(270))));

#[derive(Debug, Snafu)]
pub enum HookError {
    #[snafu(display("Scanner error: {error:#?}"))]
    ScannerError { error: ScannerError },

    #[snafu(display("signature not found: {signature}"))]
    SignatureNotFound { signature: &'static str },

    #[snafu(display("An error occured hooking game functions"))]
    DetourError { error: retour::Error },
}

pub fn attach_all() -> Result<(), HookError> {
    let scanner = Scanner::new().map_err(|error| HookError::ScannerError { error })?;

    macro_rules! attach_hook {
        ($name:literal, $retour_static:ident, $signature:literal, $detour:ident$(,)?) => {
            let address = scan_signature(&scanner, $signature)?;

            unsafe {
                debug!("{}={address:p}", $name);
                $retour_static
                    .initialize(mem::transmute::<_, _>(address), $detour)
                    .map_err(|e| HookError::DetourError { error: e })?;
            }
        };
    }

    resolve_functions(&scanner)?;
    attach_hook!(
        "projGame::PlayMusic::State_Play_initFunc",
        HookPlayMusicStatePlayInitFunc,
        "53 55 56 57 8B D9 6A ?? 68",
        hook_playmusic_state_play_initfunc,
    );
    attach_hook!(
        "projGame::PlayMusic::State_Play_updateFunc",
        HookPlayMusicStatePlayUpdateFunc,
        "53 56 57 6A ?? 8B F1 E8 ?? ?? ?? ?? 6A ?? 8B CE E8 ?? ?? ?? ?? 8B 1D",
        hook_playmusic_state_play_updatefunc,
    );
    attach_hook!(
        "projGame::TrackResult::GetLostScore",
        HookGetLostScore,
        "E8 ?? ?? ?? ?? 8B 4F ?? 2B D8",
        hook_get_lost_score,
    );
    attach_hook!(
        "projGame::JudgeContext::GetLifeRemaining",
        HookGetLifeRemaining,
        "E8 ?? ?? ?? ?? 8B F8 8D 4E ?? B8",
        hook_get_life_remaining,
    );
    attach_hook!(
        "projView::UserDataManager::Impl::AddPlayRecord",
        HookUserDataManagerImplAddPlayRecord,
        "55 8D AC 24 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 85 ?? ?? ?? ?? 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B F9 89 7D ?? 8B 85 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? 8B CB",
        hook_user_data_manager_impl_add_play_record,
    );
    Ok(())
}

fn scan_signature(scanner: &Scanner, signature: &'static str) -> Result<*const c_void, HookError> {
    scanner
        .scan_text(signature)
        .ok_or_else(|| HookError::SignatureNotFound { signature })
}

fn resolve_functions(scanner: &Scanner) -> Result<(), HookError> {
    macro_rules! resolve_function {
        ($name:literal, $oncelock:ident, $signature:literal$(,)?) => {
            let address = scan_signature(scanner, $signature)?;

            debug!("{}={address:p}", $name);

            unsafe {
                $oncelock.get_or_init(|| mem::transmute::<_, _>(address));
            }
        };
    }

    resolve_function!(
        "SkillIdToClearType",
        SKILL_ID_TO_CLEAR_TYPE,
        "53 B3 ?? 38 5C 24",
    );
    resolve_function!(
        "UserDataManager::GetUserData",
        USER_DATA_MANAGER_GET_USER_DATA,
        "E8 ?? ?? ?? ?? 89 B0",
    );
    resolve_function!(
        "UserDataManager::GetClassEmblemBase",
        USER_DATA_MANAGER_GET_CLASS_EMBLEM_BASE,
        "E8 ?? ?? ?? ?? 0F 10 45 ?? 89 43",
    );
    resolve_function!(
        "UserDataManager::GetClassEmblemMedal",
        USER_DATA_MANAGER_GET_CLASS_EMBLEM_MEDAL,
        "E8 ?? ?? ?? ?? 8B CF 89 45 ?? E8 ?? ?? ?? ?? 8D 4D",
    );
    resolve_function!(
        "GetJudgeContext",
        GET_JUDGE_CONTEXT,
        "E8 ?? ?? ?? ?? 8D 48 ?? E8 ?? ?? ?? ?? 50 8D 8E",
    );
    resolve_function!(
        "JudgeContext::GetTrackResult",
        JUDGE_CONTEXT_GET_TRACK_RESULT,
        "E8 ?? ?? ?? ?? 8B D8 8B CB 89 9D",
    );
    resolve_function!(
        "CountGuiltyJudgeTotal",
        COUNT_GUILTY_JUDGE_TOTAL,
        "55 56 57 8B E9 33 F6",
    );

    let address = scan_signature(scanner, "8D 8B ?? ?? ?? ?? FF 77")?;

    unsafe {
        let offset = usize::from_le_bytes(
            std::slice::from_raw_parts(address.cast::<u8>().byte_add(2), 4)
                .try_into()
                .expect("slice::from_raw_parts with len=4 should convert to [u8; 4]"),
        );

        debug!("offsetof(UserDataManagerImpl, playRecords)=0x{:X}", offset);

        USER_DATA_MANAGER_IMPL_PLAY_RECORDS_OFFSET.get_or_init(|| offset);
    }

    Ok(())
}

pub fn enable_all() -> Result<(), HookError> {
    macro_rules! enable_hook {
        ($retour_static:ident) => {
            $retour_static
                .enable()
                .map_err(|e| HookError::DetourError { error: e })?;
        };
    }

    unsafe {
        enable_hook!(HookPlayMusicStatePlayInitFunc);
        enable_hook!(HookPlayMusicStatePlayUpdateFunc);
        enable_hook!(HookGetLostScore);
        enable_hook!(HookGetLifeRemaining);
        enable_hook!(HookUserDataManagerImplAddPlayRecord);
    }

    Ok(())
}

pub fn disable_all() -> Result<(), HookError> {
    macro_rules! disable_hook {
        ($retour_static:ident) => {
            $retour_static
                .disable()
                .map_err(|e| HookError::DetourError { error: e })?;
        };
    }

    unsafe {
        disable_hook!(HookPlayMusicStatePlayInitFunc);
        disable_hook!(HookPlayMusicStatePlayUpdateFunc);
        disable_hook!(HookGetLostScore);
        disable_hook!(HookGetLifeRemaining);
        disable_hook!(HookUserDataManagerImplAddPlayRecord);
    }

    Ok(())
}

fn hook_playmusic_state_play_initfunc(this: *mut c_void, edx: *mut c_void) {
    unsafe {
        HookPlayMusicStatePlayInitFunc.call(this, edx);
    }

    debug!("projGame::PlayMusic::State_Play_initFunc called, clearing graph state.");

    let mut score_graph = match SCORE_GRAPH_VALUES.lock() {
        Ok(g) => g,
        Err(e) => {
            error!("Failed to acquire mutex for score graph: {e:#?}");
            return;
        }
    };
    let mut life_graph = match LIFE_GRAPH_VALUES.lock() {
        Ok(g) => g,
        Err(e) => {
            error!("Failed to acquire mutex for life graph: {e:#?}");
            return;
        }
    };
    let Some(get_judge_context) = GET_JUDGE_CONTEXT.get() else {
        error!("UserDataManager::GetJudgeContext was not initialized.");
        return;
    };

    let life_remaining = unsafe {
        let judge_context = get_judge_context();
        HookGetLifeRemaining.call(judge_context, ptr::null_mut())
    };

    score_graph.clear();
    life_graph.clear();
    GRAPH_LAST_RECORDED.store(0, Ordering::Relaxed);
    LOST_SCORE.store(0, Ordering::Relaxed);
    LIFE_REMAINING.store(life_remaining, Ordering::Relaxed);
}

fn hook_playmusic_state_play_updatefunc(this: *mut c_void, edx: *mut c_void) {
    unsafe {
        HookPlayMusicStatePlayUpdateFunc.call(this, edx);
    }

    let current_time_ns = perf_counter_ns();
    let current_time = Duration::from_nanos(current_time_ns);
    let last_recorded_ns = GRAPH_LAST_RECORDED.load(Ordering::Acquire);
    let last_recorded = Duration::from_nanos(last_recorded_ns);
    let elapsed = (current_time - last_recorded).as_secs();

    if elapsed < 1 {
        return;
    }

    let lost_score = LOST_SCORE.load(Ordering::Acquire);
    let life_remaining = LIFE_REMAINING.load(Ordering::Acquire);

    debug!(
        "projGame::PlayMusic::State_Play_updateFunc tick: last={last_recorded_ns} current={current_time_ns} elapsed_secs={elapsed} lost_score={lost_score} life_remaining={life_remaining}"
    );

    GRAPH_LAST_RECORDED.store(current_time_ns, Ordering::Release);

    match SCORE_GRAPH_VALUES.lock() {
        Ok(mut g) => {
            g.push(1_010_000 - lost_score);
        }
        Err(e) => {
            error!("Failed to acquire mutex for score graph: {e:#?}");
            return;
        }
    };

    match LIFE_GRAPH_VALUES.lock() {
        Ok(mut g) => {
            g.push(life_remaining);
        }
        Err(e) => {
            error!("Failed to acquire mutex for life graph: {e:#?}");
            return;
        }
    };
}

fn hook_get_lost_score(this: *const c_void, edx: *mut c_void) -> i32 {
    let lost_score = unsafe { HookGetLostScore.call(this, edx) };

    LOST_SCORE.store(lost_score, Ordering::Release);

    lost_score
}

fn hook_get_life_remaining(this: *const JudgeContext, edx: *mut c_void) -> i32 {
    let life_remaining = unsafe { HookGetLifeRemaining.call(this, edx) };

    LIFE_REMAINING.store(life_remaining, Ordering::Release);

    life_remaining
}

fn hook_user_data_manager_impl_add_play_record(
    this: *mut UserDataManagerImpl,
    edx: *mut c_void,
    track: i32,
    music_key: *mut c_void,
    judge_ctx: *const JudgeContext,
    a4: *mut c_void,
    a5: *mut c_void,
    option_flags: u32,
) {
    debug!("Entered UserDataManager::Impl::AddPlayRecord hook");

    unsafe {
        HookUserDataManagerImplAddPlayRecord.call(
            this,
            edx,
            track,
            music_key,
            judge_ctx,
            a4,
            a5,
            option_flags,
        );
    }

    debug!("Called original UserDataManager::Impl::AddPlayRecord");

    let Some(config) = CONFIG.get() else {
        error!("Config has not been initialized?");
        return;
    };

    let Some(user_data_manager_get_user_data) = USER_DATA_MANAGER_GET_USER_DATA.get() else {
        error!("UserDataManager::GetUserData was not resolved.");
        return;
    };
    let Some(user_data_manager_get_class_emblem_base) =
        USER_DATA_MANAGER_GET_CLASS_EMBLEM_BASE.get()
    else {
        error!("UserDataManager::GetClassEmblemBase was not resolved.");
        return;
    };
    let Some(user_data_manager_get_class_emblem_medal) =
        USER_DATA_MANAGER_GET_CLASS_EMBLEM_MEDAL.get()
    else {
        error!("UserDataManager::GetClassEmblemMedal was not resolved.");
        return;
    };
    let Some(skill_id_to_clear_type) = SKILL_ID_TO_CLEAR_TYPE.get() else {
        error!("SkillIdToClearType was not resolved.");
        return;
    };
    let Some(play_records_offset) = USER_DATA_MANAGER_IMPL_PLAY_RECORDS_OFFSET.get() else {
        error!("UserDataManager::Impl.playRecords offset was not known at initialization!");
        return;
    };
    let Some(judge_context_get_track_result) = JUDGE_CONTEXT_GET_TRACK_RESULT.get() else {
        error!("JudgeContext::GetTrackResult was not resolved.");
        return;
    };
    let score_graph = match SCORE_GRAPH_VALUES.lock() {
        Ok(g) => g,
        Err(e) => {
            error!("Failed to acquire mutex for score graph: {e:#?}");
            return;
        }
    };
    let life_graph = match LIFE_GRAPH_VALUES.lock() {
        Ok(g) => g,
        Err(e) => {
            error!("Failed to acquire mutex for life graph: {e:#?}");
            return;
        }
    };

    let udm = UserDataManager {
        vtable: ptr::null_mut(),
        implementation: this,
    };
    let user_data = unsafe { user_data_manager_get_user_data(&raw const udm) };

    debug!(
        "UserDataManager::GetUserData(impl={:p})={:p}",
        this, user_data
    );

    let access_code = unsafe { (*user_data).access_code.to_string() };

    debug!("Current player's access code: {}", access_code);

    let Some(api_key) = config
        .cards
        .get(&access_code)
        .or_else(|| config.cards.get("default"))
    else {
        info!("No API keys was assigned to card {access_code}, and no default API key was set, skipping score import.");
        return;
    };

    let play_records = unsafe {
        this.byte_add(*play_records_offset)
            .cast::<StdList<PlayRecord>>()
    };
    let play_record = unsafe { &(*(*(*play_records).head).previous).value };
    let Ok(difficulty) = Difficulty::try_from(play_record.level) else {
        error!("Unknown difficulty index {}", play_record.level);
        return;
    };
    let note_lamp = if play_record.score == 1_010_000 {
        NoteLamp::AllJusticeCritical
    } else if play_record.is_all_justice {
        NoteLamp::AllJustice
    } else if play_record.is_full_combo {
        NoteLamp::FullCombo
    } else {
        NoteLamp::None
    };
    let clear_lamp_index_if_clear =
        unsafe { skill_id_to_clear_type(&raw const play_record.skill_id, ptr::null_mut(), false) };
    let clear_lamp = if play_record.is_clear {
        let mode = unsafe { (*this).mode };
        let is_skill_inactive = mode == GameMode::Course
            || mode == GameMode::UnlockChallenge
            || mode == GameMode::LinkedVerse;

        match clear_lamp_index_if_clear {
            _ if is_skill_inactive => ClearLamp::Clear,
            1 => ClearLamp::Clear,
            2 => ClearLamp::Hard,
            3 => ClearLamp::Brave,
            4 => ClearLamp::Absolute,
            6 => ClearLamp::Catastrophy,
            _ => {
                error!("Unknown clear lamp index {}", clear_lamp_index_if_clear);
                return;
            }
        }
    } else {
        ClearLamp::Failed
    };

    // FAST/LATE counts only track TAP notes on ATTACK/JUSTICE/CRITICAL judgements
    let track_result = unsafe { judge_context_get_track_result(judge_ctx) };

    debug!(
        "JudgeContext::GetTrackResult({:p})={:p}",
        judge_ctx, track_result
    );

    let tc = unsafe { &(*track_result).judge_stats.tap.timing_counts };
    let fast = tc.attack.fast + tc.justice.fast + tc.justice_critical.fast;
    let slow = tc.attack.late + tc.justice.late + tc.justice_critical.late;

    let score_graph_data = score_graph.clone();
    let life_graph_data = life_graph.clone();

    let tachi_score = BatchManualScore {
        match_type: if difficulty == Difficulty::WorldsEnd {
            MatchType::GcmInGameIdSpecialChart
        } else {
            MatchType::InGameId
        },
        identifier: play_record.music_id.to_string(),
        difficulty: if difficulty == Difficulty::WorldsEnd {
            None
        } else {
            Some(difficulty)
        },
        score: play_record.score as u32,
        note_lamp,
        clear_lamp,
        judgements: Some(Judgements {
            jcrit: play_record.judge_heaven as u32 + play_record.judge_critical as u32,
            justice: play_record.judge_justice as u32,
            attack: play_record.judge_attack as u32,
            miss: play_record.judge_guilty as u32,
        }),
        time_achieved: Some(play_record.user_play_date as i64 * 1000),
        optional: Some(OptionalMetrics {
            fast: Some(fast as u32),
            slow: Some(slow as u32),
            max_combo: Some(play_record.max_combo as u32),
            score_graph: Some(score_graph_data),
            // if this is a hard+ clear then there's a life gauge involved
            // this is a hack but i'm not sure what to do otherwise, since
            // the game also just maps skill categories to clear lamps
            life_graph: if clear_lamp_index_if_clear > 1 {
                Some(life_graph_data)
            } else {
                None
            },
        }),
    };

    let batch_manual = BatchManualImport {
        meta: BatchManualMeta::default(),
        scores: vec![tachi_score],
        classes: Some(BatchManualClasses {
            dan: ClassEmblem::try_from(unsafe {
                user_data_manager_get_class_emblem_medal(&raw const udm)
            })
            .ok(),
            emblem: ClassEmblem::try_from(unsafe {
                user_data_manager_get_class_emblem_base(&raw const udm)
            })
            .ok(),
        }),
    };

    debug!("Executing Tachi import with batch manual {batch_manual:#?}");

    thread::spawn(move || {
        if let Err(e) = execute_score_import(batch_manual, &access_code, api_key, config) {
            error!("Failed to execute score import: {e:#?}");
        }
    });
}
