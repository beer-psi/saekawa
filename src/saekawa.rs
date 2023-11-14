use std::{ffi::CString, ptr};

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
    helpers::{call_tachi, read_hinternet_url, read_potentially_deflated_buffer},
    types::{
        game::UpsertUserAllRequest,
        tachi::{ClassEmblem, Import, ImportClasses, ImportScore},
    },
    CONFIGURATION, TACHI_IMPORT_URL,
};

type WinHttpWriteDataFunc = unsafe extern "system" fn(HINTERNET, LPCVOID, DWORD, LPDWORD) -> BOOL;

static_detour! {
    static DetourWriteData: unsafe extern "system" fn (HINTERNET, LPCVOID, DWORD, LPDWORD) -> BOOL;
}

pub fn hook_init() -> Result<()> {
    if !CONFIGURATION.general.enable {
        return Ok(());
    }

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

    let url = match read_hinternet_url(h_request) {
        Ok(url) => url,
        Err(err) => {
            error!("There was an error reading the request URL: {:#}", err);
            return DetourWriteData.call(
                h_request,
                lp_buffer,
                dw_number_of_bytes_to_write,
                lpdw_number_of_bytes_written,
            );
        }
    };
    debug!("winhttpwritedata URL: {url}");

    let request_body = match read_potentially_deflated_buffer(
        lp_buffer as *const u8,
        dw_number_of_bytes_to_write as usize,
    ) {
        Ok(data) => data,
        Err(err) => {
            error!("There was an error reading the request body: {:#}", err);
            return DetourWriteData.call(
                h_request,
                lp_buffer,
                dw_number_of_bytes_to_write,
                lpdw_number_of_bytes_written,
            );
        }
    };
    debug!("winhttpwritedata request body: {request_body}");

    if !url.contains("UpsertUserAllApi") {
        return DetourWriteData.call(
            h_request,
            lp_buffer,
            dw_number_of_bytes_to_write,
            lpdw_number_of_bytes_written,
        );
    }

    let upsert_req = match serde_json::from_str::<UpsertUserAllRequest>(&request_body) {
        Ok(req) => req,
        Err(err) => {
            error!("Could not parse request body: {:#}", err);
            return DetourWriteData.call(
                h_request,
                lp_buffer,
                dw_number_of_bytes_to_write,
                lpdw_number_of_bytes_written,
            );
        }
    };

    debug!("Parsed request body: {:#?}", upsert_req);

    let user_data = &upsert_req.upsert_user_all.user_data[0];
    let access_code = &user_data.access_code;
    if !CONFIGURATION.cards.whitelist.is_empty()
        && !CONFIGURATION.cards.whitelist.contains(access_code)
    {
        info!("Card {access_code} is not whitelisted, skipping score submission");
        return DetourWriteData.call(
            h_request,
            lp_buffer,
            dw_number_of_bytes_to_write,
            lpdw_number_of_bytes_written,
        );
    }

    let import = Import {
        classes: if CONFIGURATION.general.export_class {
            Some(ImportClasses {
                dan: ClassEmblem::try_from(user_data.class_emblem_medal).ok(),
                emblem: ClassEmblem::try_from(user_data.class_emblem_base).ok(),
            })
        } else {
            None
        },
        scores: upsert_req
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
            .collect(),
        ..Default::default()
    };

    match call_tachi("POST", TACHI_IMPORT_URL.as_str(), Some(import)) {
        Ok(_) => info!("Successfully imported scores for card {access_code}"),
        Err(err) => error!("Could not import scores for card {access_code}: {:#}", err),
    };

    DetourWriteData.call(
        h_request,
        lp_buffer,
        dw_number_of_bytes_to_write,
        lpdw_number_of_bytes_written,
    )
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
