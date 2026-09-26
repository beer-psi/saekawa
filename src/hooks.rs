use std::{
    ffi::c_void,
    mem::{self, MaybeUninit},
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, LazyLock, Mutex, OnceLock,
    },
    thread,
    time::Duration,
};

use lightningscanner::{ScanMode, Scanner};
use log::{debug, error, info};
use retour::static_detour;
use snafu::Snafu;
use winapi::um::{
    errhandlingapi::GetLastError,
    libloaderapi::GetModuleHandleW,
    processthreadsapi::GetCurrentProcess,
    psapi::{GetModuleInformation, MODULEINFO},
};

use crate::{
    helpers::{defer::defer, winapi_ext::perf_counter_ns},
    saekawa::CONFIG,
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
    pub static HookPlayMusicStateLoadInitFunc: unsafe extern "fastcall" fn(
        *mut c_void, *mut c_void
    );
    pub static HookJudgeContextOnJudge: unsafe extern "fastcall" fn(
        *mut JudgeContext, *mut c_void, u32, *const i32, u32, *const u8, u32
    );
    pub static HookSkillPlayingEvalDeathPenaltyUnit: unsafe extern "fastcall" fn(
        *mut c_void, *mut c_void, *const c_void, *const i32, *mut c_void, *mut f64, *mut bool
    ) -> bool;
    pub static HookUserDataManagerImplAddPlayRecord: unsafe extern "fastcall" fn(
        *mut UserDataManagerImpl, *mut c_void, i32, *mut c_void, *const JudgeContext, *mut c_void, *mut c_void, u32
    );
}

type SkillIdToClearTypeFn = unsafe extern "fastcall" fn(*const i32, *mut c_void, bool) -> u8;
type UserDataManagerGetUserDataFn =
    unsafe extern "fastcall" fn(*const UserDataManager) -> *const UserData;
type JudgeContextGetTrackResultFn =
    unsafe extern "fastcall" fn(*const JudgeContext) -> *const TrackResult;
type CountGuiltyJudgeTotalFn =
    unsafe extern "fastcall" fn(*const c_void, *mut c_void, *const u8) -> i32;

static SKILL_ID_TO_CLEAR_TYPE: OnceLock<SkillIdToClearTypeFn> = OnceLock::new();
static USER_DATA_MANAGER_GET_USER_DATA: OnceLock<UserDataManagerGetUserDataFn> = OnceLock::new();
static JUDGE_CONTEXT_GET_TRACK_RESULT: OnceLock<JudgeContextGetTrackResultFn> = OnceLock::new();
static COUNT_GUILTY_JUDGE_TOTAL: OnceLock<CountGuiltyJudgeTotalFn> = OnceLock::new();

static USER_DATA_MANAGER_IMPL_PLAY_RECORDS_OFFSET: OnceLock<usize> = OnceLock::new();

static GRAPH_LAST_RECORDED: AtomicU64 = AtomicU64::new(0);
static SCORE_GRAPH_VALUES: LazyLock<Arc<Mutex<Vec<i32>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(Vec::with_capacity(270))));
static LIFE_GRAPH_VALUES: LazyLock<Arc<Mutex<Vec<i32>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(Vec::with_capacity(270))));
static SHOULD_GRAPH_LIFE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Snafu)]
pub enum HookError {
    #[snafu(display("Win32 error: {error}"))]
    Win32Error { error: u32 },

    #[snafu(display("Could not find signature in game binary: {signature}"))]
    SignatureNotFound { signature: &'static str },

    #[snafu(display("An error occured hooking game functions"))]
    DetourError { error: retour::Error },
}

pub fn attach_all() -> Result<(), HookError> {
    let mut module_info: MaybeUninit<MODULEINFO> = MaybeUninit::uninit();
    let result = unsafe {
        GetModuleInformation(
            GetCurrentProcess(),
            GetModuleHandleW(ptr::null_mut()),
            module_info.as_mut_ptr(),
            mem::size_of::<MODULEINFO>() as u32,
        )
    };

    if result == 0 {
        return Err(HookError::Win32Error {
            error: unsafe { GetLastError() },
        });
    }

    // TODO: scan a copy of the image instead of the actual image itself
    // to prevent conflicts with other hooks

    let module_info = unsafe { module_info.assume_init() };
    let scan_mode = if is_x86_feature_detected!("avx2") {
        ScanMode::Avx2
    } else if is_x86_feature_detected!("sse4.2") {
        ScanMode::Sse42
    } else {
        ScanMode::Scalar
    };

    debug!(
        "lpBaseOfDll={:p} SizeOfImage={} scan_mode={:?}",
        module_info.lpBaseOfDll, module_info.SizeOfImage, scan_mode
    );

    resolve_functions(&module_info, scan_mode)?;
    attach_hook_playmusic_state_load_initfunc(&module_info, scan_mode)?;
    attach_hook_judge_context_on_judge(&module_info, scan_mode)?;
    attach_hook_skill_playing_eval_death_penalty_unit(&module_info, scan_mode)?;
    attach_hook_user_data_manager_impl_add_play_record(&module_info, scan_mode)?;
    Ok(())
}

fn scan_signature(
    module_info: &MODULEINFO,
    scan_mode: ScanMode,
    signature: &'static str,
) -> Result<*const u8, HookError> {
    let scanner = Scanner::new(signature);
    let result = unsafe {
        scanner.find(
            Some(scan_mode),
            module_info.lpBaseOfDll.cast::<_>(),
            module_info.SizeOfImage as _,
        )
    };

    if !result.is_valid() {
        return Err(HookError::SignatureNotFound { signature });
    }

    let address = result.get_addr();
    let b = unsafe { *address };

    if b == 0xE8 || b == 0xE9 {
        unsafe {
            let rel = i32::from_le_bytes(
                std::slice::from_raw_parts(address.byte_add(1), 4)
                    .try_into()
                    .expect("std::slice::from_raw_parts with len=4 should convert to [u8; 4]"),
            );

            Ok(address.add(5).offset(rel as isize))
        }
    } else {
        Ok(address)
    }
}

fn resolve_functions(module_info: &MODULEINFO, scan_mode: ScanMode) -> Result<(), HookError> {
    let address = scan_signature(module_info, scan_mode, "53 B3 ?? 38 5C 24")?;

    unsafe {
        debug!("SkillIdToClearType={:p}", address);
        SKILL_ID_TO_CLEAR_TYPE.get_or_init(|| mem::transmute::<_, _>(address));
    }

    let address = scan_signature(module_info, scan_mode, "E8 ?? ?? ?? ?? 89 B0")?;

    unsafe {
        debug!("UserDataManager::GetUserData={:p}", address);
        USER_DATA_MANAGER_GET_USER_DATA.get_or_init(|| mem::transmute::<_, _>(address));
    }

    let address = scan_signature(module_info, scan_mode, "8D 8B ?? ?? ?? ?? FF 77")?;

    unsafe {
        let offset = usize::from_le_bytes(
            std::slice::from_raw_parts(address.byte_add(2), 4)
                .try_into()
                .expect("slice::from_raw_parts with len=4 should convert to [u8; 4]"),
        );

        debug!("offsetof(UserDataManagerImpl, playRecords)=0x{:X}", offset);

        USER_DATA_MANAGER_IMPL_PLAY_RECORDS_OFFSET.get_or_init(|| offset);
    }

    let address = scan_signature(module_info, scan_mode, "E8 ?? ?? ?? ?? 8B D8 8B CB 89 9D")?;

    unsafe {
        debug!("JudgeContext::GetTrackResult={:p}", address);
        JUDGE_CONTEXT_GET_TRACK_RESULT.get_or_init(|| mem::transmute::<_, _>(address));
    }

    let address = scan_signature(module_info, scan_mode, "55 56 57 8B E9 33 F6")?;

    unsafe {
        debug!("CountGuiltyJudgeTotal={:p}", address);
        COUNT_GUILTY_JUDGE_TOTAL.get_or_init(|| mem::transmute::<_, _>(address));
    }

    Ok(())
}

fn attach_hook_playmusic_state_load_initfunc(
    module_info: &MODULEINFO,
    scan_mode: ScanMode,
) -> Result<(), HookError> {
    let address = scan_signature(
        module_info,
        scan_mode,
        "55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 8D 89"
    )?;

    unsafe {
        debug!("projGame::PlayMusic::State_Load_initFunc={:p}", address);
        HookPlayMusicStateLoadInitFunc
            .initialize(
                mem::transmute::<_, _>(address),
                hook_play_music_state_load_initfunc,
            )
            .map_err(|e| HookError::DetourError { error: e })?;
    }

    Ok(())
}

fn attach_hook_judge_context_on_judge(
    module_info: &MODULEINFO,
    scan_mode: ScanMode,
) -> Result<(), HookError> {
    let address = scan_signature(
        module_info,
        scan_mode,
        "81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 55 56 ",
    )?;

    unsafe {
        debug!("JudgeContext::OnJudge={:p}", address);
        HookJudgeContextOnJudge
            .initialize(mem::transmute::<_, _>(address), hook_judge_context_on_judge)
            .map_err(|e| HookError::DetourError { error: e })?;
    }

    Ok(())
}

fn attach_hook_skill_playing_eval_death_penalty_unit(
    module_info: &MODULEINFO,
    scan_mode: ScanMode,
) -> Result<(), HookError> {
    let address = scan_signature(module_info, scan_mode, "83 EC ?? 53 55 8B 6C 24 ?? 32 DB")?;

    unsafe {
        debug!("SkillPlaying::EvalDeathPenaltyUnit={:p}", address);
        HookSkillPlayingEvalDeathPenaltyUnit
            .initialize(
                mem::transmute::<_, _>(address),
                hook_skill_playing_eval_death_penalty_unit,
            )
            .map_err(|e| HookError::DetourError { error: e })?;
    }

    Ok(())
}

fn attach_hook_user_data_manager_impl_add_play_record(
    module_info: &MODULEINFO,
    scan_mode: ScanMode,
) -> Result<(), HookError> {
    let address = scan_signature(
        module_info,
        scan_mode,
        "55 8D AC 24 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 85 ?? ?? ?? ?? 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B F9 89 7D ?? 8B 85 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? 8B CB",
    )?;

    unsafe {
        debug!("UserDataManager::Impl::AddPlayRecord={:p}", address);
        HookUserDataManagerImplAddPlayRecord
            .initialize(
                mem::transmute::<_, _>(address),
                hook_user_data_manager_impl_add_play_record,
            )
            .map_err(|e| HookError::DetourError { error: e })?;
    }

    Ok(())
}

pub fn enable_all() -> Result<(), HookError> {
    unsafe {
        HookPlayMusicStateLoadInitFunc
            .enable()
            .map_err(|e| HookError::DetourError { error: e })?;
        HookJudgeContextOnJudge
            .enable()
            .map_err(|e| HookError::DetourError { error: e })?;
        HookSkillPlayingEvalDeathPenaltyUnit
            .enable()
            .map_err(|e| HookError::DetourError { error: e })?;
        HookUserDataManagerImplAddPlayRecord
            .enable()
            .map_err(|e| HookError::DetourError { error: e })?;
    }

    Ok(())
}

pub fn disable_all() -> Result<(), HookError> {
    unsafe {
        HookPlayMusicStateLoadInitFunc
            .disable()
            .map_err(|e| HookError::DetourError { error: e })?;
        HookUserDataManagerImplAddPlayRecord
            .disable()
            .map_err(|e| HookError::DetourError { error: e })?;
        HookJudgeContextOnJudge
            .disable()
            .map_err(|e| HookError::DetourError { error: e })?;
        HookSkillPlayingEvalDeathPenaltyUnit
            .disable()
            .map_err(|e| HookError::DetourError { error: e })?;
    }

    Ok(())
}

fn hook_play_music_state_load_initfunc(this: *mut c_void, edx: *mut c_void) {
    unsafe {
        HookPlayMusicStateLoadInitFunc.call(this, edx);
    }

    debug!("projGame::PlayMusic::State_Load_initFunc called, clearing graph state.");

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

    score_graph.clear();
    life_graph.clear();
    GRAPH_LAST_RECORDED.store(0, Ordering::Relaxed);
    SHOULD_GRAPH_LIFE.store(false, Ordering::Release);
}

fn hook_judge_context_on_judge(
    this: *mut JudgeContext,
    edx: *mut c_void,
    judge_info_id: u32,
    note_type: *const i32,
    note_info_id: u32,
    judge_kind: *const u8,
    timing_slot: u32,
) {
    // We do processing before the original function because the original function
    // calls our SkillPlaying::evalDeathPenaltyUnit hook, which we use to track
    // life counts. However, that one is also called by *another* function
    // before the first note is ever hit, so there are stray data points in the
    // graph if we don't control when we do our processing with `SHOULD_GRAPH_LIFE`.
    let _call_original = defer(|| unsafe {
        HookJudgeContextOnJudge.call(
            this,
            edx,
            judge_info_id,
            note_type,
            note_info_id,
            judge_kind,
            timing_slot,
        )
    });

    let last_recorded = Duration::from_nanos(GRAPH_LAST_RECORDED.load(Ordering::Relaxed));
    let current_time = perf_counter_ns();
    let elapsed = (Duration::from_nanos(current_time) - last_recorded).as_secs();

    if elapsed < 1 {
        return;
    }

    let Some(judge_context_get_track_result) = JUDGE_CONTEXT_GET_TRACK_RESULT.get() else {
        error!("JudgeContext::GetTrackResult address is unknown");
        return;
    };
    let mut score_graph = match SCORE_GRAPH_VALUES.lock() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to acquire mutex for score graph: {e:#?}");
            return;
        }
    };

    let tr = unsafe { judge_context_get_track_result(this) };
    let score_lost = unsafe { (*tr).judge_stats.score_lost };
    let remaining_score = 1_010_000 - score_lost;

    if score_graph.is_empty() {
        score_graph.push(1_010_000);
    }

    score_graph.push(remaining_score);
    GRAPH_LAST_RECORDED.store(current_time, Ordering::Relaxed);

    debug!("JudgeContext::OnJudge: score={}", remaining_score);

    SHOULD_GRAPH_LIFE.store(true, Ordering::Release);
}

fn hook_skill_playing_eval_death_penalty_unit(
    this: *mut c_void,
    edx: *mut c_void,
    skill_config: *const c_void,
    event: *const i32,
    a3: *mut c_void,
    gauge: *mut f64,
    death_flag: *mut bool,
) -> bool {
    let result = unsafe {
        HookSkillPlayingEvalDeathPenaltyUnit.call(
            this,
            edx,
            skill_config,
            event,
            a3,
            gauge,
            death_flag,
        )
    };

    if !SHOULD_GRAPH_LIFE.fetch_and(false, Ordering::AcqRel) {
        return result;
    }

    let Some(count_guilty_judge_total) = COUNT_GUILTY_JUDGE_TOTAL.get() else {
        error!("CountGuiltyJudgeTotal address is unknown");
        return result;
    };
    let mut life_graph = match LIFE_GRAPH_VALUES.lock() {
        Ok(g) => g,
        Err(e) => {
            error!("Failed to acquire mutex for life graph: {e:#?}");
            return result;
        }
    };

    let threshold = unsafe { skill_config.byte_add(0x0C).cast::<u8>() };
    let initial_gauge = unsafe { *skill_config.byte_add(0x10).cast::<i32>() };
    let gauge_lost =
        unsafe { count_guilty_judge_total(event as *const _, ptr::null_mut(), threshold) };

    if life_graph.is_empty() {
        life_graph.push(initial_gauge);
    }

    life_graph.push(initial_gauge - gauge_lost);

    debug!(
        "SkillPlaying::EvalDeathPenaltyUnit: initial={} lost={} remaining={}",
        initial_gauge,
        gauge_lost,
        initial_gauge - gauge_lost
    );

    result
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
        error!("UserDataManager::GetUserData was somehow not set at initialization!");
        return;
    };
    let Some(skill_id_to_clear_type) = SKILL_ID_TO_CLEAR_TYPE.get() else {
        error!("SkillIdToClearType was somehow not set at initialization!");
        return;
    };
    let Some(play_records_offset) = USER_DATA_MANAGER_IMPL_PLAY_RECORDS_OFFSET.get() else {
        error!("UserDataManager::Impl.playRecords offset was not known at initialization!");
        return;
    };
    let Some(judge_context_get_track_result) = JUDGE_CONTEXT_GET_TRACK_RESULT.get() else {
        error!("JudgeContext::GetTrackResult was somehow not set at initialization!");
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

    let user_data = unsafe {
        // a bit hacky but who cares unless it blows up in my face down the line
        // the vtable is just the dtor anyways
        let udm = UserDataManager {
            vtable: ptr::null_mut(),
            implementation: this,
        };

        user_data_manager_get_user_data(&raw const udm)
    };

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
        match_type: MatchType::InGameId,
        identifier: play_record.music_id.to_string(),
        difficulty: Some(difficulty),
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
            dan: ClassEmblem::try_from(unsafe { (*user_data).class_emblem_medal }).ok(),
            emblem: ClassEmblem::try_from(unsafe { (*user_data).class_emblem_base }).ok(),
        }),
    };

    debug!("Executing Tachi import with batch manual {batch_manual:#?}");

    thread::spawn(move || {
        if let Err(e) = execute_score_import(batch_manual, &access_code, api_key, config) {
            error!("Failed to execute score import: {e:#?}");
        }
    });
}
