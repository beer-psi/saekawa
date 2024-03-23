use std::{
    fmt::Debug,
    fs::File,
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, AtomicU16, Ordering},
};

use ::log::{debug, error, info};
use anyhow::{anyhow, Result};
use log::warn;
use serde::de::DeserializeOwned;
use widestring::U16CString;
use winapi::{
    ctypes::c_void,
    shared::minwindef::{BOOL, DWORD, FALSE, LPCVOID, LPDWORD, LPVOID, MAX_PATH},
    um::{errhandlingapi::GetLastError, winbase::GetPrivateProfileStringW, winhttp::HINTERNET},
};

use crate::{
    configuration::{Configuration, GeneralConfiguration},
    handlers::score_handler,
    helpers::{
        decrypt_aes256_cbc, is_encrypted_endpoint, is_endpoint, read_hinternet_url,
        read_hinternet_user_agent, read_maybe_compressed_buffer, read_slice, request_tachi,
    },
    icf::{decode_icf, IcfData},
    types::{
        game::{UpsertUserAllRequest, UserMusicResponse},
        tachi::{StatusCheck, TachiResponse, ToTachiImport},
    },
    CONFIGURATION, GET_USER_MUSIC_API_ENCRYPTED, TACHI_STATUS_URL, UPSERT_USER_ALL_API_ENCRYPTED,
};

pub static GAME_MAJOR_VERSION: AtomicU16 = AtomicU16::new(0);
pub static PB_IMPORTED: AtomicBool = AtomicBool::new(true);

pub fn hook_init() -> Result<()> {
    if !CONFIGURATION.general.enable {
        return Ok(());
    }

    if CONFIGURATION.general.export_pbs {
        warn!("===============================================================================");
        warn!("Exporting PBs is enabled. This should only be used once to sync up your scores!");
        warn!("Leaving it on can make your profile messy! This will be automatically be turned off after exporting is finished.");
        warn!("You can check when it's done by searching for the message 'Submitting x scores from user ID xxxxx'.");
        warn!("===============================================================================");

        PB_IMPORTED.store(false, Ordering::SeqCst);
    }

    debug!("Retrieving AMFS path from segatools.ini");

    let mut buf = [0u16; MAX_PATH];
    let amfs_cfg = unsafe {
        let sz = GetPrivateProfileStringW(
            U16CString::from_str_unchecked("vfs").as_ptr(),
            U16CString::from_str_unchecked("amfs").as_ptr(),
            U16CString::new().as_ptr(),
            buf.as_mut_ptr(),
            MAX_PATH as u32,
            U16CString::from_str(".\\segatools.ini").unwrap().as_ptr(),
        );

        if sz == 0 {
            let ec = GetLastError();
            return Err(anyhow!(
                "AMFS path not specified in segatools.ini, error code {ec}"
            ));
        }

        match U16CString::from_ptr(buf.as_ptr(), sz as usize) {
            Ok(data) => data.to_string_lossy(),
            Err(err) => {
                return Err(anyhow!(
                    "could not read AMFS path from segatools.ini: {:#}",
                    err
                ));
            }
        }
    };
    let amfs_path = Path::new(&amfs_cfg);
    let icf1_path = amfs_path.join("ICF1");

    if !icf1_path.exists() {
        return Err(anyhow!("Could not find ICF1 inside AMFS path. You will probably not be able to network without this file, so this hook will also be disabled."));
    }

    debug!("Reading ICF1 located at {:?}", icf1_path);

    let mut icf1_buf = {
        let mut icf1_file = File::open(icf1_path)?;
        let mut icf1_buf = Vec::new();
        icf1_file.read_to_end(&mut icf1_buf)?;
        icf1_buf
    };
    let icf = decode_icf(&mut icf1_buf).map_err(|err| anyhow!("Reading ICF failed: {:#}", err))?;

    for entry in icf {
        if let IcfData::App(app) = entry {
            info!("Running on {} {}", app.id, app.version);
            GAME_MAJOR_VERSION.store(app.version.major, Ordering::Relaxed);
        }
    }

    debug!("Pinging Tachi API for status check and token verification");

    let resp: TachiResponse<StatusCheck> =
        request_tachi("GET", TACHI_STATUS_URL.as_str(), None::<()>)?;
    let user_id = match resp {
        TachiResponse::Err(err) => {
            return Err(anyhow!("Tachi API returned an error: {}", err.description));
        }
        TachiResponse::Ok(resp) => {
            if !resp.body.permissions.iter().any(|v| v == "submit_score") {
                return Err(anyhow!(
                    "API key has insufficient permissions. The permission submit_score must be set."
                ));
            }

            let Some(user_id) = resp.body.whoami else {
                return Err(anyhow!(
                    "Status check was successful, yet API returned userID null?"
                ));
            };

            user_id
        }
    };

    info!("Logged in to Tachi with userID {user_id}");

    debug!("Initializing detours");

    crochet::enable!(winhttpwritedata_hook_wrapper)?;

    if CONFIGURATION.general.export_pbs || cfg!(debug_assertions) {
        crochet::enable!(winhttpreaddata_hook_wrapper)?;
    }

    info!("Hook successfully initialized");

    Ok(())
}

pub fn hook_release() -> Result<()> {
    if !CONFIGURATION.general.enable {
        return Ok(());
    }

    if crochet::is_enabled!(winhttpreaddata_hook_wrapper) {
        crochet::disable!(winhttpreaddata_hook_wrapper)?;
    }

    if crochet::is_enabled!(winhttpwritedata_hook_wrapper) {
        crochet::disable!(winhttpwritedata_hook_wrapper)?;
    }

    Ok(())
}

#[crochet::hook(compile_check, "winhttp.dll", "WinHttpReadData")]
fn winhttpreaddata_hook_wrapper(
    h_request: HINTERNET,
    lp_buffer: LPVOID,
    dw_number_of_bytes_to_read: DWORD,
    lpdw_number_of_bytes_read: LPDWORD,
) -> BOOL {
    debug!("hit winhttpreaddata");

    let result = call_original!(
        h_request,
        lp_buffer,
        dw_number_of_bytes_to_read,
        lpdw_number_of_bytes_read
    );

    if result == FALSE {
        let ec = unsafe { GetLastError() };
        error!("Calling original WinHttpReadData function failed: {ec}");
        return result;
    }

    let pb_imported = PB_IMPORTED.load(Ordering::SeqCst);
    if cfg!(not(debug_assertions)) && pb_imported {
        return result;
    }

    if let Err(err) = winhttprwdata_hook::<UserMusicResponse>(
        h_request,
        lp_buffer,
        dw_number_of_bytes_to_read,
        "GetUserMusicApi",
        &GET_USER_MUSIC_API_ENCRYPTED,
        move |_| {
            if pb_imported {
                return false;
            }

            PB_IMPORTED.store(true, Ordering::Relaxed);
            if let Err(err) = Configuration::update(Configuration {
                general: GeneralConfiguration {
                    export_pbs: false,
                    ..CONFIGURATION.general
                },
                cards: CONFIGURATION.cards.clone(),
                crypto: CONFIGURATION.crypto.clone(),
                tachi: CONFIGURATION.tachi.clone(),
            }) {
                error!("Could not update configuration to disable exporting PBs: {err:?}");
            }

            true
        },
    ) {
        error!("{err:?}");
    }

    result
}

#[crochet::hook(compile_check, "winhttp.dll", "WinHttpWriteData")]
fn winhttpwritedata_hook_wrapper(
    h_request: HINTERNET,
    lp_buffer: LPCVOID,
    dw_number_of_bytes_to_write: DWORD,
    lpdw_number_of_bytes_written: LPDWORD,
) -> BOOL {
    debug!("hit winhttpwritedata");

    if let Err(err) = winhttprwdata_hook::<UpsertUserAllRequest>(
        h_request,
        lp_buffer,
        dw_number_of_bytes_to_write,
        "UpsertUserAllApi",
        &UPSERT_USER_ALL_API_ENCRYPTED,
        |upsert_req| {
            let user_data = &upsert_req.upsert_user_all.user_data[0];
            let access_code = &user_data.access_code;
            if !CONFIGURATION.cards.whitelist.is_empty()
                && !CONFIGURATION.cards.whitelist.contains(access_code)
            {
                info!("Card {access_code} is not whitelisted, skipping score submission");
                return false;
            }

            true
        },
    ) {
        error!("{err:?}");
    }

    call_original!(
        h_request,
        lp_buffer,
        dw_number_of_bytes_to_write,
        lpdw_number_of_bytes_written
    )
}

/// Common hook for WinHttpWriteData/WinHttpReadData. The flow is similar for both
/// hooks:
/// - Read URL and User-Agent from the handle
/// - Extract the API method from the URL, and exit if it's not the method we're
/// looking for
/// - Determine if the API is encrypted, and exit if it is and we don't have keys
/// - Parse the body and convert it to Tachi's BATCH-MANUAL
/// - Submit it off to Tachi, if our guard function (which takes the parsed body) allows so.
fn winhttprwdata_hook<'a, T: Debug + DeserializeOwned + ToTachiImport + 'static>(
    handle: HINTERNET,
    buffer: *const c_void,
    bufsz: DWORD,
    unencrypted_endpoint: &str,
    encrypted_endpoint: &Option<String>,
    guard_fn: impl Fn(&T) -> bool + Send + 'static,
) -> Result<()> {
    let url = read_hinternet_url(handle)?;
    let user_agent = read_hinternet_user_agent(handle)?;
    debug!("user-agent {user_agent}, URL: {url}");

    let maybe_endpoint = url
        .split('/')
        .last()
        .ok_or(anyhow!("Could not extract last part of a split URL"))?;

    let is_encrypted = is_encrypted_endpoint(maybe_endpoint);

    let endpoint = if is_encrypted && user_agent.contains('#') {
        user_agent
            .split('#')
            .next()
            .ok_or(anyhow!("there should be at least one item in the split"))?
    } else {
        maybe_endpoint
    };

    let is_correct_endpoint = is_endpoint(endpoint, unencrypted_endpoint, encrypted_endpoint);
    if cfg!(not(debug_assertions)) && !is_correct_endpoint {
        return Ok(());
    }

    if is_encrypted && (CONFIGURATION.crypto.key.is_empty() || CONFIGURATION.crypto.iv.is_empty()) {
        return Err(anyhow!("Communications with the server is encrypted, but no keys were provided. Fill in the keys by editing 'saekawa.toml'."));
    }

    let mut raw_body = match read_slice(buffer as *const u8, bufsz as usize) {
        Ok(data) => data,
        Err(err) => {
            return Err(anyhow!(
                "There was an error reading the response body: {:#}",
                err
            ));
        }
    };

    debug!("raw body: {}", faster_hex::hex_string(&raw_body));

    std::thread::spawn(move || {
        let compressed_body = if is_encrypted {
            match decrypt_aes256_cbc(
                &mut raw_body,
                &CONFIGURATION.crypto.key,
                &CONFIGURATION.crypto.iv,
            ) {
                Ok(res) => res,
                Err(err) => {
                    error!("Could not decrypt response: {:#}", err);
                    return;
                }
            }
        } else {
            raw_body
        };

        let body = match read_maybe_compressed_buffer(&compressed_body[..]) {
            Ok(data) => data,
            Err(err) => {
                error!("There was an error decoding the request body: {:#}", err);
                return;
            }
        };

        debug!("decoded response body: {body}");

        // Hit in debug build
        if !is_correct_endpoint {
            return;
        }

        score_handler::<T>(body, guard_fn)
    });

    Ok(())
}
