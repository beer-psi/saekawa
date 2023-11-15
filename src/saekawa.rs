use std::{ffi::CString, io::Read, ptr};

use ::log::{debug, error, info};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{anyhow, Result};
use flate2::read::ZlibDecoder;
use retour::static_detour;
use winapi::{
    ctypes::c_void,
    shared::minwindef::{__some_function, BOOL, DWORD, LPCVOID, LPDWORD},
    um::{
        errhandlingapi::GetLastError,
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        winhttp::HINTERNET,
    },
};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

use crate::{
    helpers::{
        self, call_tachi, is_encrypted_endpoint, is_upsert_user_all_endpoint, read_hinternet_url,
        read_potentially_deflated_buffer,
    },
    types::{
        game::UpsertUserAllRequest,
        tachi::{ClassEmblem, Import, ImportClasses, ImportScore},
    },
    CONFIGURATION, TACHI_IMPORT_URL, TACHI_STATUS_URL,
};

type WinHttpWriteDataFunc = unsafe extern "system" fn(HINTERNET, LPCVOID, DWORD, LPDWORD) -> BOOL;

static_detour! {
    static DetourWriteData: unsafe extern "system" fn (HINTERNET, LPCVOID, DWORD, LPDWORD) -> BOOL;
}

pub fn hook_init() -> Result<()> {
    if !CONFIGURATION.general.enable {
        return Ok(());
    }

    let resp: serde_json::Value =
        helpers::request_tachi("GET", TACHI_STATUS_URL.as_str(), None::<()>)?;
    let user_id = resp["body"]["whoami"]
        .as_u64()
        .ok_or(anyhow::anyhow!("Couldn't parse user from Tachi response"))?;

    info!("Logged in to Tachi with userID {user_id}");

    let winhttpwritedata = unsafe {
        let addr = get_proc_address("winhttp.dll", "WinHttpWriteData")
            .map_err(|err| anyhow!("{:#}", err))?;
        std::mem::transmute::<_, WinHttpWriteDataFunc>(addr)
    };

    unsafe {
        DetourWriteData.initialize(winhttpwritedata, move |a, b, c, d| {
            winhttpwritedata_hook(a, b, c, d)
        })?;

        DetourWriteData.enable()?;
    };

    info!("Hook successfully initialized");
    Ok(())
}

pub fn hook_release() -> Result<()> {
    if !CONFIGURATION.general.enable {
        return Ok(());
    }

    unsafe { DetourWriteData.disable()? };

    Ok(())
}

unsafe fn winhttpwritedata_hook(
    h_request: HINTERNET,
    lp_buffer: LPCVOID,
    dw_number_of_bytes_to_write: DWORD,
    lpdw_number_of_bytes_written: LPDWORD,
) -> BOOL {
    debug!("hit winhttpwritedata");

    let orig = || {
        DetourWriteData.call(
            h_request,
            lp_buffer,
            dw_number_of_bytes_to_write,
            lpdw_number_of_bytes_written,
        )
    };

    let url = match read_hinternet_url(h_request) {
        Ok(url) => url,
        Err(err) => {
            error!("There was an error reading the request URL: {:#}", err);
            return orig();
        }
    };
    debug!("winhttpwritedata URL: {url}");

    let endpoint = match url.split('/').last() {
        Some(endpoint) => endpoint,
        None => {
            error!("Could not get name of endpoint");
            return orig();
        }
    };

    let is_encrypted = is_encrypted_endpoint(endpoint);
    if is_encrypted
        && (CONFIGURATION.crypto.key.is_empty()
            || CONFIGURATION.crypto.iv.is_empty()
            || CONFIGURATION.crypto.salt.is_empty())
    {
        error!("Communications with the server is encrypted, but no keys were provided. Fill in the keys by editing 'saekawa.toml'.");
        return orig();
    }

    let is_upsert_user_all = is_upsert_user_all_endpoint(endpoint, is_encrypted);
    // Exit early if release mode and the endpoint is not what we're looking for
    if cfg!(not(debug_assertions)) && !is_upsert_user_all {
        return orig();
    }

    let raw_request_body = match read_potentially_deflated_buffer(
        lp_buffer as *const u8,
        dw_number_of_bytes_to_write as usize,
    ) {
        Ok(data) => data,
        Err(err) => {
            error!("There was an error reading the request body: {:#}", err);
            return orig();
        }
    };

    let request_body_decrypted = if is_encrypted {
        // TODO: Decrypt
        Vec::new()
    } else {
        raw_request_body
    };

    let mut request_body_bytes = Vec::with_capacity(request_body_decrypted.len());
    let mut decoder = ZlibDecoder::new(&request_body_decrypted[..]);
    if let Err(err) = decoder.read_to_end(&mut request_body_bytes) {
        debug!(
            "Could not inflate request body, treating it as uncompressed: {:#}",
            err
        );
        request_body_bytes = request_body_decrypted;
    }

    let request_body = match String::from_utf8(request_body_bytes) {
        Ok(data) => data,
        Err(err) => {
            error!("There was an error decoding the request body: {:#}", err);
            return orig();
        }
    };

    debug!("winhttpwritedata request body: {request_body}");

    // Reached in debug mode
    if !is_upsert_user_all {
        return orig();
    }

    let upsert_req = match serde_json::from_str::<UpsertUserAllRequest>(&request_body) {
        Ok(req) => req,
        Err(err) => {
            error!("Could not parse request body: {:#}", err);
            return orig();
        }
    };

    debug!("Parsed request body: {:#?}", upsert_req);

    let user_data = &upsert_req.upsert_user_all.user_data[0];
    let access_code = &user_data.access_code;
    if !CONFIGURATION.cards.whitelist.is_empty()
        && !CONFIGURATION.cards.whitelist.contains(access_code)
    {
        info!("Card {access_code} is not whitelisted, skipping score submission");
        return orig();
    }

    let classes = if CONFIGURATION.general.export_class {
        Some(ImportClasses {
            dan: ClassEmblem::try_from(user_data.class_emblem_medal).ok(),
            emblem: ClassEmblem::try_from(user_data.class_emblem_base).ok(),
        })
    } else {
        None
    };

    let scores = upsert_req
        .upsert_user_all
        .user_playlog_list
        .into_iter()
        .filter_map(|playlog| {
            if let Ok(score) = ImportScore::try_from(playlog) {
                if score.difficulty.as_str() == "WORLD'S END" {
                    return None;
                }
                Some(score)
            } else {
                None
            }
        })
        .collect::<Vec<ImportScore>>();

    if scores.is_empty() {
        if classes.is_none() {
            return orig();
        }

        if classes
            .clone()
            .is_some_and(|v| v.dan.is_none() && v.emblem.is_none())
        {
            return orig();
        }
    }

    let import = Import {
        classes,
        scores,
        ..Default::default()
    };

    match call_tachi("POST", TACHI_IMPORT_URL.as_str(), Some(import)) {
        Ok(_) => info!("Successfully imported scores for card {access_code}"),
        Err(err) => error!("Could not import scores for card {access_code}: {:#}", err),
    };

    orig()
}

fn get_proc_address(module: &str, function: &str) -> Result<*mut __some_function> {
    let module_name = CString::new(module).unwrap();
    let fun_name = CString::new(function).unwrap();

    let module = unsafe { GetModuleHandleA(module_name.as_ptr()) };
    if (module as *const c_void) == ptr::null() {
        let ec = unsafe { GetLastError() };
        return Err(anyhow!("could not get module handle, error code {ec}"));
    }

    let addr = unsafe { GetProcAddress(module, fun_name.as_ptr()) };
    if (addr as *const c_void) == ptr::null() {
        let ec = unsafe { GetLastError() };
        return Err(anyhow!("could not get function address, error code {ec}"));
    }

    Ok(addr)
}
