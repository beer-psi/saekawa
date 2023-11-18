use std::ptr;

use anyhow::{anyhow, Result};
use widestring::U16CString;
use winapi::{
    ctypes::c_void,
    shared::{minwindef::TRUE, winerror::ERROR_INSUFFICIENT_BUFFER},
    um::{
        errhandlingapi::GetLastError,
        winhttp::{
            WinHttpQueryHeaders, WinHttpQueryOption, HINTERNET, WINHTTP_OPTION_URL,
            WINHTTP_QUERY_FLAG_REQUEST_HEADERS, WINHTTP_QUERY_USER_AGENT,
        },
    },
};

/// Queries a HINTERNET handle for its URL, then return the result.
pub fn read_hinternet_url(handle: HINTERNET) -> Result<String> {
    let mut buf_length = 255;
    let mut buffer = [0u16; 255];
    let result = unsafe {
        WinHttpQueryOption(
            handle,
            WINHTTP_OPTION_URL,
            buffer.as_mut_ptr() as *mut c_void,
            &mut buf_length,
        )
    };

    if result == TRUE {
        let url_str = U16CString::from_vec_truncate(&buffer[..buf_length as usize]);
        return url_str
            .to_string()
            .map_err(|err| anyhow!("Could not decode wide string: {:#}", err));
    }

    let ec = unsafe { GetLastError() };
    if ec == ERROR_INSUFFICIENT_BUFFER {
        let mut buffer = vec![0u16; buf_length as usize];
        let result = unsafe {
            WinHttpQueryOption(
                handle,
                WINHTTP_OPTION_URL,
                buffer.as_mut_ptr() as *mut c_void,
                &mut buf_length,
            )
        };

        if result != TRUE {
            let ec = unsafe { GetLastError() };
            return Err(anyhow!("Could not get URL from HINTERNET handle: {ec}"));
        }

        let url_str = U16CString::from_vec_truncate(&buffer[..buf_length as usize]);
        return url_str
            .to_string()
            .map_err(|err| anyhow!("Could not decode wide string: {:#}", err));
    }

    let ec = unsafe { GetLastError() };
    Err(anyhow!("Could not get URL from HINTERNET handle: {ec}"))
}

pub fn read_hinternet_user_agent(handle: HINTERNET) -> Result<String> {
    let mut buf_length = 255;
    let mut buffer = [0u16; 255];
    let result = unsafe {
        WinHttpQueryHeaders(
            handle,
            WINHTTP_QUERY_USER_AGENT | WINHTTP_QUERY_FLAG_REQUEST_HEADERS,
            ptr::null(),
            buffer.as_mut_ptr() as *mut c_void,
            &mut buf_length,
            ptr::null_mut(),
        )
    };

    if result == TRUE {
        let user_agent_str = U16CString::from_vec_truncate(&buffer[..buf_length as usize]);
        return user_agent_str
            .to_string()
            .map_err(|err| anyhow!("Could not decode wide string: {:#}", err));
    }

    let ec = unsafe { GetLastError() };
    if ec == ERROR_INSUFFICIENT_BUFFER {
        let mut buffer = vec![0u16; buf_length as usize];
        let result = unsafe {
            WinHttpQueryHeaders(
                handle,
                WINHTTP_QUERY_USER_AGENT | WINHTTP_QUERY_FLAG_REQUEST_HEADERS,
                ptr::null(),
                buffer.as_mut_ptr() as *mut c_void,
                &mut buf_length,
                ptr::null_mut(),
            )
        };

        if result != TRUE {
            let ec = unsafe { GetLastError() };
            return Err(anyhow!("Could not get URL from HINTERNET handle: {ec}"));
        }

        let user_agent_str = U16CString::from_vec_truncate(&buffer[..buf_length as usize]);
        return user_agent_str
            .to_string()
            .map_err(|err| anyhow!("Could not decode wide string: {:#}", err));
    }

    let ec = unsafe { GetLastError() };
    Err(anyhow!(
        "Could not get User-Agent from HINTERNET handle: {ec}"
    ))
}
