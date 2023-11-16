use std::ffi::CString;

use ::log::{debug, error, info};
use anyhow::{anyhow, Result};
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

use crate::{
    helpers::{
        call_tachi, decrypt_aes256_cbc, is_encrypted_endpoint, is_upsert_user_all_endpoint,
        read_hinternet_url, read_maybe_compressed_buffer, read_slice, request_tachi,
    },
    types::{
        game::UpsertUserAllRequest,
        tachi::{ClassEmblem, Difficulty, Import, ImportClasses, ImportScore},
    },
    CONFIGURATION, TACHI_IMPORT_URL, TACHI_STATUS_URL, UPSERT_USER_ALL_API_ENCRYPTED,
};

type WinHttpWriteDataFunc = unsafe extern "system" fn(HINTERNET, LPCVOID, DWORD, LPDWORD) -> BOOL;

static_detour! {
    static DetourWriteData: unsafe extern "system" fn (HINTERNET, LPCVOID, DWORD, LPDWORD) -> BOOL;
}

pub fn hook_init() -> Result<()> {
    if !CONFIGURATION.general.enable {
        return Ok(());
    }

    let resp: serde_json::Value = request_tachi("GET", TACHI_STATUS_URL.as_str(), None::<()>)?;
    let user_id = resp["body"]["whoami"]
        .as_u64()
        .ok_or(anyhow::anyhow!("Couldn't parse user from Tachi response"))?;

    let mut permissions = resp["body"]["permissions"]
        .as_array()
        .ok_or(anyhow!("Couldn't parse permissions from Tachi response"))?
        .into_iter()
        .filter_map(|v| v.as_str());

    if permissions.all(|v| v != "submit_score") {
        return Err(anyhow!(
            "API key has insufficient permission. The permission submit_score must be set."
        ));
    }

    info!("Logged in to Tachi with userID {user_id}");

    let winhttpwritedata = unsafe {
        let addr = get_proc_address("winhttp.dll", "WinHttpWriteData")
            .map_err(|err| anyhow!("{:#}", err))?;
        std::mem::transmute::<_, WinHttpWriteDataFunc>(addr)
    };

    unsafe {
        DetourWriteData
            .initialize(winhttpwritedata, winhttpwritedata_hook)?
            .enable()?;
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

fn winhttpwritedata_hook(
    h_request: HINTERNET,
    lp_buffer: LPCVOID,
    dw_number_of_bytes_to_write: DWORD,
    lpdw_number_of_bytes_written: LPDWORD,
) -> BOOL {
    debug!("hit winhttpwritedata");

    let orig = || unsafe {
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

    let Some(endpoint) = url.split('/').last() else {
        error!("Could not get name of endpoint");
        return orig();
    };

    let is_upsert_user_all = is_upsert_user_all_endpoint(endpoint);
    // Exit early if release mode and the endpoint is not what we're looking for
    if cfg!(not(debug_assertions)) && !is_upsert_user_all {
        return orig();
    }

    let is_encrypted = is_encrypted_endpoint(endpoint);
    if is_encrypted
        && (CONFIGURATION.crypto.key.is_empty()
            || CONFIGURATION.crypto.iv.is_empty()
            || UPSERT_USER_ALL_API_ENCRYPTED.is_none())
    {
        error!("Communications with the server is encrypted, but no keys were provided. Fill in the keys by editing 'saekawa.toml'.");
        return orig();
    }

    let mut raw_request_body =
        match read_slice(lp_buffer as *const u8, dw_number_of_bytes_to_write as usize) {
            Ok(data) => data,
            Err(err) => {
                error!("There was an error reading the request body: {:#}", err);
                return orig();
            }
        };

    debug!("raw request body: {:?}", raw_request_body);

    let request_body_compressed = if is_encrypted {
        match decrypt_aes256_cbc(
            &mut raw_request_body,
            &CONFIGURATION.crypto.key,
            &CONFIGURATION.crypto.iv,
        ) {
            Ok(res) => res,
            Err(err) => {
                error!("Could not decrypt request: {:#}", err);
                return orig();
            }
        }
    } else {
        raw_request_body
    };

    let request_body = match read_maybe_compressed_buffer(&request_body_compressed[..]) {
        Ok(data) => data,
        Err(err) => {
            error!("There was an error decoding the request body: {:#}", err);
            return orig();
        }
    };

    debug!("decoded request body: {request_body}");

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
            let result =
                ImportScore::try_from_playlog(playlog, CONFIGURATION.general.fail_over_lamp);
            if result
                .as_ref()
                .is_ok_and(|v| v.difficulty != Difficulty::WorldsEnd)
            {
                result.ok()
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
    if (module as *const c_void).is_null() {
        let ec = unsafe { GetLastError() };
        return Err(anyhow!("could not get module handle, error code {ec}"));
    }

    let addr = unsafe { GetProcAddress(module, fun_name.as_ptr()) };
    if (addr as *const c_void).is_null() {
        let ec = unsafe { GetLastError() };
        return Err(anyhow!("could not get function address, error code {ec}"));
    }

    Ok(addr)
}
