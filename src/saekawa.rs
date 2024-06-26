use std::{
    io::{self, Read},
    mem::{self, MaybeUninit},
    num::ParseIntError,
    ptr,
    sync::OnceLock,
    thread,
};

use ini::Ini;
use log::{debug, error, info};
use snafu::{prelude::Snafu, ResultExt};
use winapi::{
    shared::minwindef::{BOOL, DWORD, LPCVOID, LPDWORD},
    um::{
        errhandlingapi::GetLastError,
        libloaderapi::GetModuleHandleW,
        processthreadsapi::GetCurrentProcess,
        psapi::{GetModuleInformation, MODULEINFO},
        winhttp::{HINTERNET, WINHTTP_OPTION_URL},
    },
};

use crate::{
    config::{ConfigLoadError, SaekawaConfig},
    helpers::{
        chuni_encoding::{decrypt_aes256_cbc, hash_endpoint, maybe_decompress_buffer},
        winapi_ext::{winhttp_query_option, ReadStringFnError},
    },
    score_import::execute_score_import,
    sigscan::{self, CryptoKeys},
    types::{chuni::UpsertUserAllRequest, ToBatchManual},
};

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

    #[snafu(display("An error occured calling a Win32 function: {errno}"))]
    Win32Error { errno: u32 },

    #[snafu(display("Could not find a pattern in the game executable"))]
    CryptoScanError { source: sigscan::CryptoScanError },

    #[snafu(display("The configured path for failed import exists and is not a directory."))]
    FailedImportNotDir,

    #[snafu(display("Could not create the configured directory for failed imports."))]
    FailedCreatingFailedImportDir { source: io::Error },
}

#[derive(Debug, Snafu)]
pub enum ProcessRequestError {
    #[snafu(display("Could not read URL from HINTERNET handle"))]
    UrlReadError { source: ReadStringFnError },

    #[snafu(display("The URL does not have an endpoint"))]
    UrlMissingEndpointError,

    #[snafu(display(
        "Hooked function was called before all necessary state has been initialized"
    ))]
    UninitializedError,

    #[snafu(display("Could not read request body"))]
    ReadBodyError { source: io::Error },
}

#[derive(Debug, Clone)]
struct GameInformation {
    pub game_id: String,
    pub major: u16,
    pub minor: u8,
    pub build: u8,
}

/// This is used by the Tachi <-> CHUNITHM conversion functions,
/// because some enum indexes changed between CHUNITHM and CHUNITHM NEW,
/// namely difficulty, and later on, clear lamps.
static GAME_MAJOR_VERSION: OnceLock<u16> = OnceLock::new();
static CRYPTO_KEYS: OnceLock<CryptoKeys> = OnceLock::new();
static UPSERT_USER_ALL_API: OnceLock<String> = OnceLock::new();

static CONFIG: OnceLock<SaekawaConfig> = OnceLock::new();

pub fn hook_init() -> Result<(), HookError> {
    debug!("Reading hook configuration");
    let config = SaekawaConfig::load().context(ConfigSnafu)?;

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

    CONFIG
        .set(config)
        .expect("OnceLock shouldn't be initialized.");

    debug!("Reading version information from project.conf");
    let info = get_project_conf()?;

    info!(
        "Running on {} {}.{:0>2}.{:0>2}",
        info.game_id, info.major, info.minor, info.build
    );

    let ver = determine_major_version(&info);

    debug!("Game's major version is {ver}");

    GAME_MAJOR_VERSION
        .set(ver)
        .expect("OnceLock shouldn't be initialized.");

    debug!("Checking if network requests are encrypted");
    setup_network_encryption(&info)?;

    crochet::enable!(winhttpwritedata_hook).context(CrochetSnafu)?;
    info!("Hooks enabled.");

    Ok(())
}

pub fn hook_release() -> Result<(), HookError> {
    if crochet::is_enabled!(winhttpwritedata_hook) {
        crochet::disable!(winhttpwritedata_hook).context(CrochetSnafu)?;
    }

    info!("Hooks disabled.");

    Ok(())
}

#[crochet::hook(compile_check, "winhttp.dll", "WinHttpWriteData")]
fn winhttpwritedata_hook(
    hrequest: HINTERNET,
    lp_buffer: LPCVOID,
    dw_n_bytes_to_write: DWORD,
    lpdw_n_bytes_written: LPDWORD,
) -> BOOL {
    if let Err(e) = process_request(hrequest, lp_buffer, dw_n_bytes_to_write) {
        error!("{e:#?}");
    }

    call_original!(
        hrequest,
        lp_buffer,
        dw_n_bytes_to_write,
        lpdw_n_bytes_written
    )
}

fn process_request(
    hrequest: HINTERNET,
    buffer: LPCVOID,
    bufsiz: DWORD,
) -> Result<(), ProcessRequestError> {
    let url = winhttp_query_option(hrequest, WINHTTP_OPTION_URL).context(UrlReadSnafu)?;

    debug!("Captured request to {url}");

    let endpoint = url
        .split('/')
        .last()
        .ok_or(ProcessRequestError::UrlMissingEndpointError)?;
    let upsert_user_all_endpoint = UPSERT_USER_ALL_API
        .get()
        .ok_or(ProcessRequestError::UninitializedError)?;

    if endpoint != upsert_user_all_endpoint {
        return Ok(());
    }

    info!("Received profile upsert request. Initiating score import...");

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

    thread::spawn(move || {
        let Some(config) = CONFIG.get() else {
            error!("Config has not been initialized?");
            return;
        };

        let Some(major_version) = GAME_MAJOR_VERSION.get() else {
            error!("The game's major version is not known?");
            return;
        };

        let compressed_body = if let Some(keys) = CRYPTO_KEYS.get() {
            match decrypt_aes256_cbc(&mut raw_body, &keys.key, &keys.iv) {
                Ok(r) => r,
                Err(e) => {
                    error!("Could not decrypt request: {e:#?}");
                    return;
                }
            }
        } else {
            raw_body
        };

        let body = match maybe_decompress_buffer(&compressed_body) {
            Ok(s) => s,
            Err(e) => {
                error!("Could not read request as DEFLATE-compressed or plaintext: {e:#?}");
                return;
            }
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

        let import = data.to_batch_manual(
            *major_version,
            config.general.export_class,
            config.general.fail_over_lamp,
        );

        if let Err(e) = execute_score_import(import, access_code, &tachi_api_key, &config) {
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

fn setup_network_encryption(info: &GameInformation) -> Result<(), HookError> {
    debug!("Getting module information of the game process");
    let mut modinfo: MaybeUninit<MODULEINFO> = MaybeUninit::uninit();
    let result = unsafe {
        GetModuleInformation(
            GetCurrentProcess(),
            GetModuleHandleW(ptr::null_mut()),
            modinfo.as_mut_ptr(),
            mem::size_of::<MODULEINFO>() as u32,
        )
    };

    if result == 0 {
        let err = unsafe { GetLastError() };

        error!("Could not get information about the game process, error code {err}");
        return Err(HookError::Win32Error { errno: err });
    }

    let modinfo = unsafe { modinfo.assume_init() };
    debug!(
        "Base address: {:p}, image size: {:x}",
        modinfo.lpBaseOfDll, modinfo.SizeOfImage
    );

    debug!("Scanning game for encryption status");
    let encryption_enabled = unsafe {
        sigscan::is_network_encrypted(modinfo.lpBaseOfDll as *const _, modinfo.SizeOfImage as _)
            .context(CryptoScanSnafu)?
    };

    let endpoint = if info.game_id == "SDGS" {
        if info.minor < 10 {
            "UpsertUserAllApiExp"
        } else {
            "UpsertUserAllApiC3Exp"
        }
    } else {
        "UpsertUserAllApi"
    };

    if encryption_enabled {
        info!("Network requests are encrypted.");

        debug!("Searching for encryption keys. This might take a bit...");

        let keys = unsafe {
            sigscan::get_crypto_keys(modinfo.lpBaseOfDll as *const _, modinfo.SizeOfImage as _)
                .context(CryptoScanSnafu)?
        };

        debug!("Search completed successfully.");

        #[cfg(debug_assertions)]
        {
            debug!(
                "Key: {}, IV: {}, salt: {}, iterations: {}",
                faster_hex::hex_string(&keys.key),
                faster_hex::hex_string(&keys.iv),
                faster_hex::hex_string(&keys.salt),
                keys.iterations,
            )
        }

        // For some reason, CHUNITHM SUPERSTAR/SUPERSTAR+ forgot to add "Exp" when
        // hashing the endpoint.
        let endpoint_password = if info.game_id == "SDGS" && info.minor < 10 {
            "UpsertUserAllApi"
        } else {
            endpoint
        };

        let hashed_endpoint = hash_endpoint(endpoint_password, &keys.salt, keys.iterations);

        debug!(
            "Hashed {endpoint_password} with {:#?} to {hashed_endpoint}",
            keys.salt
        );

        UPSERT_USER_ALL_API
            .set(hashed_endpoint)
            .expect("OnceLock shouldn't be initialized.");
        CRYPTO_KEYS
            .set(keys)
            .expect("OnceLock shouldn't be initialized.");
    } else {
        info!("Network requests are not encrypted.");

        UPSERT_USER_ALL_API
            .set(endpoint.to_string())
            .expect("OnceLock shouldn't be initialized.");
    }

    Ok(())
}
