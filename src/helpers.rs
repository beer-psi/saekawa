use std::{fmt::Debug, io::Read};

use anyhow::{anyhow, Result};
use flate2::read::ZlibDecoder;
use log::debug;
use serde::{Deserialize, Serialize};
use widestring::U16CString;
use winapi::{
    ctypes::c_void,
    shared::{minwindef::TRUE, winerror::ERROR_INSUFFICIENT_BUFFER},
    um::{
        errhandlingapi::GetLastError,
        winhttp::{WinHttpQueryOption, HINTERNET, WINHTTP_OPTION_URL},
    },
};

use crate::CONFIGURATION;

pub fn request_agent() -> ureq::Agent {
    let timeout = CONFIGURATION.general.timeout;
    let timeout = if timeout > 10000 { 10000 } else { timeout };

    ureq::builder()
        .timeout(std::time::Duration::from_millis(timeout))
        .build()
}

fn request<T>(
    method: impl AsRef<str>,
    url: impl AsRef<str>,
    body: Option<T>,
) -> Result<ureq::Response>
where
    T: Serialize + Debug,
{
    let agent = request_agent();

    let method = method.as_ref();
    let url = url.as_ref();
    debug!("{} request to {} with body: {:#?}", method, url, body);

    let authorization = format!("Bearer {}", CONFIGURATION.tachi.api_key);
    let request = agent
        .request(method, url)
        .set("Authorization", authorization.as_str());
    let response = match body {
        Some(body) => request.send_json(body),
        None => request.call(),
    }
    .map_err(|err| anyhow::anyhow!("Could not reach Tachi API: {:#}", err))?;

    Ok(response)
}

pub fn call_tachi<T>(method: impl AsRef<str>, url: impl AsRef<str>, body: Option<T>) -> Result<()>
where
    T: Serialize + Debug,
{
    let response = request(method, url, body)?;
    let response: serde_json::Value = response.into_json()?;
    debug!("Tachi API response: {:#?}", response);

    Ok(())
}

pub fn request_tachi<T, R>(
    method: impl AsRef<str>,
    url: impl AsRef<str>,
    body: Option<T>,
) -> Result<R>
where
    T: Serialize + Debug,
    R: for<'de> Deserialize<'de> + Debug,
{
    let response = request(method, url, body)?;
    let response = response.into_json()?;
    debug!("Tachi API response: {:#?}", response);

    Ok(response)
}

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
    return Err(anyhow!("Could not get URL from HINTERNET handle: {ec}"));
}

pub fn read_potentially_deflated_buffer(buf: *const u8, len: usize) -> Result<String> {
    let mut slice = unsafe { std::slice::from_raw_parts(buf, len) };
    let mut ret = String::new();

    let mut decoder = ZlibDecoder::new(slice);
    let zlib_result = decoder.read_to_string(&mut ret);
    if zlib_result.is_ok() {
        return Ok(ret);
    }

    ret.clear();
    let result = slice.read_to_string(&mut ret);
    if result.is_ok() {
        return Ok(ret);
    }

    // Unwrapping here is fine, if result was Ok we wouldn't reach this place.
    Err(anyhow!(
        "Could not decode contents of buffer as both DEFLATE-compressed ({:#}) and plaintext ({:#}) UTF-8 string.",
        zlib_result.err().expect("This shouldn't happen, if Result was Ok the string should have been returned earlier."),
        result.err().expect("This shouldn't happen, if Result was Ok the string should have been returned earlier."),
    ))
}
