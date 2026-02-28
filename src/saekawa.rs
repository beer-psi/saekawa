use std::{
    io::{self, Read},
    num::ParseIntError,
    sync::{Arc, Condvar, LazyLock, Mutex, OnceLock},
    thread,
    time::Duration,
};

use flate2::read::ZlibDecoder;
use ini::Ini;
use log::{debug, error, info, warn};
use serde::Deserialize;
use snafu::{prelude::Snafu, ResultExt};
use winapi::{
    shared::{
        basetsd::DWORD_PTR,
        minwindef::{BOOL, DWORD, LPCVOID, LPDWORD, LPVOID},
        winerror::ERROR_INVALID_PARAMETER,
    },
    um::winhttp::{
        HINTERNET, WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE, WINHTTP_OPTION_URL,
        WINHTTP_STATUS_CALLBACK,
    },
};

use crate::{
    config::{ConfigLoadError, SaekawaConfig},
    crypto::{decrypt_aes256_cbc, get_game_crypto_information, GameCryptoInformation},
    helpers::{
        winapi_ext::{
            winhttp_query_option, winhttp_query_request_headers, LibraryHandle, ReadStringFnError,
        },
        Defer,
    },
    score_import::execute_score_import,
    types::{chuni::UpsertUserAllRequest, ToBatchManual},
};

#[cfg(feature = "autoupdate")]
use crate::updater::self_update;

#[derive(Debug, Snafu)]
pub enum HookError {
    #[snafu(display("Could not load configuration"))]
    ConfigError { source: ConfigLoadError },

    #[snafu(display("No cards were configured in the [cards] section. There is nothing to export to. Add tokens under the cards section with the format `\"access_code\" = \"tachi_api_key\"`. If you wish to export scores from all cards, use `default` in place of an access code."))]
    NoCardsError,

    #[snafu(display("An error occured hooking the underlying functions"))]
    CrochetError { source: crochet::detour::Error },

    #[snafu(display("The game version specified in project.conf is not a number."))]
    InvalidVersion { source: ParseIntError },

    #[snafu(display("An error occured parsing project.conf"))]
    IniError { source: ini::Error },

    #[snafu(display("The configured path for failed import exists and is not a directory."))]
    FailedImportNotDir,

    #[snafu(display("Could not create the configured directory for failed imports."))]
    FailedCreatingFailedImportDir { source: io::Error },
}

#[derive(Debug, Snafu)]
pub enum ProcessRequestError {
    #[snafu(display("Could not read URL from HINTERNET handle"))]
    UrlRead { source: ReadStringFnError },

    #[snafu(display("Could not read headers from HINTERNET handle"))]
    HeaderRead { source: ReadStringFnError },

    #[snafu(display("The URL does not have an endpoint"))]
    UrlMissingEndpoint,

    #[snafu(display(
        "Hooked function was called before all necessary state has been initialized"
    ))]
    UninitializedState,

    #[snafu(display("Could not read request body"))]
    ReadBody { source: io::Error },

    #[snafu(display(
        "Received encrypted request for unsupported game version. Please enable the \"No encryption\" patch on a patcher, or add encryption keys in the configuration file."
    ))]
    EncryptionNotSupported,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GameInformation {
    pub game_id: String,
    pub major: u16,
    pub minor: u8,
    pub build: u8,
}

/// This is used by the Tachi <-> CHUNITHM conversion functions,
/// because some enum indexes changed between CHUNITHM and CHUNITHM NEW,
/// namely difficulty, and later on, clear lamps.
static GAME_MAJOR_VERSION: OnceLock<u16> = OnceLock::new();
static GAME_CRYPTO_INFORMATION: OnceLock<GameCryptoInformation> = OnceLock::new();
static CONFIG: OnceLock<SaekawaConfig> = OnceLock::new();

static IS_EXECUTING_IMPORT: LazyLock<Arc<(Mutex<bool>, Condvar)>> =
    LazyLock::new(|| Arc::new((Mutex::new(false), Condvar::new())));
static CURRENT_WINHTTP_STATUS_CALLBACK: LazyLock<Arc<Mutex<WINHTTP_STATUS_CALLBACK>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));

#[cfg_attr(not(feature = "autoupdate"), allow(unused_variables))]
pub fn hook_init(library_handle: LibraryHandle) -> Result<(), HookError> {
    debug!("Reading hook configuration");
    let config = SaekawaConfig::load().context(ConfigSnafu)?;

    #[cfg(feature = "autoupdate")]
    {
        if config.general.auto_update {
            match self_update(&library_handle) {
                Ok(should_reboot) => {
                    if should_reboot {
                        info!("Self-update successful. Reloading into new hook...");
                        library_handle.free_and_exit_thread(1);
                    }
                }
                Err(e) => {
                    error!("Self-update failed: {e:#}");
                }
            }
        }
    }

    if config.cards.is_empty() {
        return Err(HookError::NoCardsError);
    }

    info!("Loaded API keys for {} access code(s).", config.cards.len());

    if let Some(d) = &config.general.failed_import_dir {
        if d.exists() && !d.is_dir() {
            return Err(HookError::FailedImportNotDir);
        }

        if !d.exists() {
            std::fs::create_dir_all(d).context(FailedCreatingFailedImportDirSnafu)?;
        }
    }

    debug!("Reading version information from project.conf");
    let info = get_project_conf()?;

    info!(
        "Running on {} {}.{:0>2}.{:0>2}",
        info.game_id, info.major, info.minor, info.build
    );

    debug!("Retrieving encryption information for this game version");
    GAME_CRYPTO_INFORMATION
        .set(get_game_crypto_information(&config, &info))
        .expect("OnceLock shouldn't be initialized.");

    let ver = determine_major_version(&info);

    debug!("Game's major version is {ver}");

    GAME_MAJOR_VERSION
        .set(ver)
        .expect("OnceLock shouldn't be initialized.");

    CONFIG
        .set(config)
        .expect("OnceLock shouldn't be initialized.");

    crochet::enable!(winhttpwritedata_hook).context(CrochetSnafu)?;
    crochet::enable!(winhttpsetstatuscallback_hook).context(CrochetSnafu)?;
    info!("Hooks enabled.");

    Ok(())
}

pub fn hook_release() -> Result<(), HookError> {
    if crochet::is_enabled!(winhttpwritedata_hook) {
        crochet::disable!(winhttpwritedata_hook).context(CrochetSnafu)?;
    }

    if crochet::is_enabled!(winhttpsetstatuscallback_hook) {
        crochet::disable!(winhttpsetstatuscallback_hook).context(CrochetSnafu)?;
    }

    info!("Hooks disabled.");

    Ok(())
}

#[allow(clippy::missing_transmute_annotations)]
#[crochet::hook("winhttp.dll", "WinHttpWriteData")]
fn winhttpwritedata_hook(
    hrequest: HINTERNET,
    lp_buffer: LPCVOID,
    dw_n_bytes_to_write: DWORD,
    lpdw_n_bytes_written: LPDWORD,
) -> BOOL {
    if let Err(e) = process_request(hrequest, lp_buffer, dw_n_bytes_to_write) {
        error!("Could not process request: {e:#?}");
    }

    call_original!(
        hrequest,
        lp_buffer,
        dw_n_bytes_to_write,
        lpdw_n_bytes_written
    )
}

#[crochet::hook("winhttp.dll", "WinHttpSetStatusCallback")]
fn winhttpsetstatuscallback_hook(
    hrequest: HINTERNET,
    lpfn_internet_callback: WINHTTP_STATUS_CALLBACK,
    dw_notification_flags: DWORD,
    dw_reserved: DWORD_PTR,
) -> WINHTTP_STATUS_CALLBACK {
    // This only gets called a single time by the network code into a single
    // function pointer, so we don't have to worry about different stuff
    // trampling on each other, at least for now.
    *CURRENT_WINHTTP_STATUS_CALLBACK.lock().unwrap() = lpfn_internet_callback;

    call_original!(
        hrequest,
        Some(winhttp_status_callback),
        dw_notification_flags,
        dw_reserved
    )
}

extern "system" fn winhttp_status_callback(
    hrequest: HINTERNET,
    dw_context: DWORD_PTR,
    dw_internet_status: DWORD,
    lpv_status_information: LPVOID,
    dw_status_information_length: DWORD,
) {
    // block the callback from being called before import is complete
    if dw_internet_status == WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE {
        let (lock, cvar) = &*IS_EXECUTING_IMPORT.clone();
        let mut executing_import = lock.lock().unwrap();

        while *executing_import {
            executing_import = cvar.wait(executing_import).unwrap();
        }
    }

    if let Some(original_callback) = *CURRENT_WINHTTP_STATUS_CALLBACK.lock().unwrap() {
        unsafe {
            original_callback(
                hrequest,
                dw_context,
                dw_internet_status,
                lpv_status_information,
                dw_status_information_length,
            );
        }
    }
}

fn process_request(
    hrequest: HINTERNET,
    buffer: LPCVOID,
    bufsiz: DWORD,
) -> Result<(), ProcessRequestError> {
    let url = match winhttp_query_option(hrequest, WINHTTP_OPTION_URL) {
        Ok(url) => url,
        Err(ReadStringFnError::Other { errno }) if errno == ERROR_INVALID_PARAMETER => {
            warn!("Unexpected ERROR_INVALID_PARAMETER when calling WinHttpQueryOption(WINHTTP_OPTION_URL). If you are running under Wine/Proton, update to at least Wine 9.13/Proton 10.0.");

            return Err(ProcessRequestError::UrlRead {
                source: ReadStringFnError::Other { errno },
            });
        }
        Err(e) => {
            return Err(ProcessRequestError::UrlRead { source: e });
        }
    };

    debug!("Captured request to {url}");

    let endpoint = url
        .split('/')
        .last()
        .ok_or(ProcessRequestError::UrlMissingEndpoint)?;
    let chuni_encoding_version =
        winhttp_query_request_headers(hrequest, "Chuni-Encoding").context(HeaderReadSnafu)?;
    let crypto_information = GAME_CRYPTO_INFORMATION
        .get()
        .ok_or(ProcessRequestError::UninitializedState)?;

    if chuni_encoding_version.is_some() {
        let Some(target_endpoint) = &crypto_information.upsert_user_all_hashed_endpoint else {
            return Err(ProcessRequestError::EncryptionNotSupported);
        };

        if endpoint != target_endpoint {
            return Ok(());
        }
    } else if endpoint != crypto_information.upsert_user_all_endpoint {
        return Ok(());
    }

    info!("Received profile upsert request. Initiating score import...");

    let content_encoding =
        winhttp_query_request_headers(hrequest, "Content-Encoding").context(HeaderReadSnafu)?;
    let (key, iv) = if chuni_encoding_version.is_some() {
        (
            crypto_information.key.clone(),
            crypto_information.iv.clone(),
        )
    } else {
        (None, None)
    };
    let mut raw_body_slice =
        unsafe { std::slice::from_raw_parts(buffer as *const u8, bufsiz as usize) };
    let mut raw_body = Vec::with_capacity(bufsiz as usize);

    raw_body_slice
        .read_to_end(&mut raw_body)
        .context(ReadBodySnafu)?;

    #[cfg(debug_assertions)]
    {
        debug!("raw request: {}", faster_hex::hex_string(&raw_body));
    }

    // Mark the import as executing from here so that callbacks
    // will block even if the response comes instantly
    let (lock, _cvar) = &*IS_EXECUTING_IMPORT.clone();
    *lock.lock().unwrap() = true;

    // Drop the block after 45s, even if the import is still ongoing
    // at Kamaitachi, since network requests time out at 60s
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(45));

        let (lock, cvar) = &*IS_EXECUTING_IMPORT.clone();
        let mut executing_import = lock.lock().unwrap();

        if *executing_import {
            *executing_import = false;
            cvar.notify_one();
        }
    });

    thread::spawn(move || {
        // Import execution should stop when this thread exits at any moment.
        // The "proper" way to do this would probably be to extract the existing
        // code out into a function but I don't careeeee
        let _defer = Defer::new(|| {
            let (lock, cvar) = &*IS_EXECUTING_IMPORT.clone();
            let mut executing_import = lock.lock().unwrap();

            if *executing_import {
                *executing_import = false;
                cvar.notify_one();
            }
        });

        let Some(config) = CONFIG.get() else {
            error!("Config has not been initialized?");
            return;
        };

        let Some(major_version) = GAME_MAJOR_VERSION.get() else {
            error!("The game's major version is not known?");
            return;
        };

        let maybe_compressed_body = if let Some(chuni_encoding_version) = chuni_encoding_version {
            if let (Some(key), Some(iv)) = (key, iv) {
                match decrypt_aes256_cbc(&mut raw_body, key, iv) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Could not decrypt request: {e:#?}");
                        return;
                    }
                }
            } else {
                error!("Received encrypted request, but missing encryption keys for Chuni-Encoding {chuni_encoding_version}");
                return;
            }
        } else {
            raw_body
        };

        let body = match content_encoding {
            Some(ce) if ce == "deflate" => {
                let mut s = String::with_capacity(maybe_compressed_body.len() * 2);
                let mut decoder = ZlibDecoder::new(&maybe_compressed_body[..]);

                match decoder.read_to_string(&mut s) {
                    Ok(_) => s,
                    Err(e) => {
                        error!("Could not read DEFLATE-compressed body as UTF-8 string: {e:?}");
                        return;
                    }
                }
            }
            Some(ce) => {
                error!("Received compressed request with unknown Content-Encoding {ce}");
                return;
            }
            None => match String::from_utf8(maybe_compressed_body) {
                Ok(s) => s,
                Err(e) => {
                    error!("Could not read uncompressed body as UTF-8 string: {e:?}");
                    return;
                }
            },
        };

        #[cfg(debug_assertions)]
        {
            debug!("decoded request: {}", body.trim());
        }

        let data = match serde_json::from_str::<UpsertUserAllRequest>(&body) {
            Ok(d) => d,
            Err(e) => {
                error!("Could not parse request: {e:#?}");
                return;
            }
        };

        let user_data = &data.upsert_user_all.user_data[0];
        let access_code = &user_data.access_code;
        let Some(tachi_api_key) = config
            .cards
            .get(access_code)
            .or_else(|| config.cards.get("default"))
        else {
            info!("No API keys was assigned to {access_code}, and no default API key was set, skipping score import.");
            return;
        };
        let current_time = jiff::Zoned::now();
        let time_difference = (&current_time - &user_data.last_play_date)
            .total(jiff::Unit::Second)
            .expect("jiff::Zoned::until should not give a span with calendar units")
            .abs();

        // Extremely generous time difference, since lastPlayDate is set right before
        // the profile is submitted
        let replace_tz = if time_difference >= 300.0 {
            warn!("+-------------------------------------------------------------------------------------+");
            warn!("|                                 CLOCK JUMP DETECTED!                                |");
            warn!("+-------------------------------------------------------------------------------------+");
            warn!("Received a profile upsert request where the last play date was more than 5 minutes ago.");
            warn!(
                "(current time: {}, last play date: {})",
                current_time.strftime("%Y-%m-%d %H:%M:%S %Z"),
                user_data
                    .last_play_date
                    .with_time_zone(current_time.time_zone().clone())
                    .strftime("%Y-%m-%d %H:%M:%S %Z")
            );
            warn!("This usually indicates that the segatools timezone hook is disabled or malfunctioning.");
            warn!("Saekawa expects timestamps from CHUNITHM to be in JST (UTC+9).");
            warn!("Invalid timestamps can cause scores to be rejected. Please double check your setup.");

            warn!("Trying to see if timestamps are actually in the system's local time...");

            // Try to replace the timezone in last_play_date with the system timezone and see if it
            // makes more sense, since that's the most common way the timestamp is fucked up
            match jiff::tz::TimeZone::try_system() {
                Ok(system_tz) => match user_data
                    .last_play_date
                    .datetime()
                    .to_zoned(system_tz.clone())
                {
                    Ok(last_play_date_as_system_time) => {
                        let time_difference_2 = (&current_time - &last_play_date_as_system_time)
                            .total(jiff::Unit::Second)
                            .expect("jiff::Zoned::until should not give a span with calendar units")
                            .abs();

                        if time_difference_2 < 300.0 {
                            warn!("Treating the timestamps as local time instead.",);
                            Some(system_tz)
                        } else {
                            warn!("Cannot treat timestamps as local time, since the time difference is still too large.");
                            warn!(
                                "(current time: {}, last play date: {})",
                                current_time.strftime("%Y-%m-%d %H:%M:%S %Z"),
                                last_play_date_as_system_time
                                    .with_time_zone(current_time.time_zone().clone())
                                    .strftime("%Y-%m-%d %H:%M:%S %Z")
                            );
                            None
                        }
                    }
                    Err(e) => {
                        warn!("Cannot replace the timestamp's timezone with the system timezone: {e:?}");
                        None
                    }
                },
                Err(e) => {
                    warn!("Cannot retrieve the system time zone: {e:?}");
                    None
                }
            }
        } else {
            None
        };

        let import = data.to_batch_manual(*major_version, config.general.export_class, replace_tz);

        if let Err(e) = execute_score_import(import, access_code, tachi_api_key, config) {
            error!("{e}");
        }
    });

    Ok(())
}

fn get_project_conf() -> Result<GameInformation, HookError> {
    let project_conf = Ini::load_from_file("./project.conf").context(IniSnafu)?;
    let major_version = &project_conf["Version"]["VerMajor"];
    let minor_version = &project_conf["Version"]["VerMinor"];
    let build_version = &project_conf["Version"]["VerRelease"];
    let game_id = &project_conf["Project"]["GameID"];

    Ok(GameInformation {
        game_id: game_id.to_string(),
        major: major_version.parse::<u16>().context(InvalidVersionSnafu)?,
        minor: minor_version.parse::<u8>().context(InvalidVersionSnafu)?,
        build: build_version.parse::<u8>().context(InvalidVersionSnafu)?,
    })
}

fn determine_major_version(info: &GameInformation) -> u16 {
    if info.game_id == "SDGS" {
        if info.minor < 10 {
            1
        } else {
            2
        }
    } else {
        info.major
    }
}
