use std::{fmt::Debug, io::Read, ptr};

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use anyhow::{anyhow, Result};
use flate2::read::ZlibDecoder;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
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

use crate::{
    types::tachi::{Import, ImportDocument, ImportPollStatus, TachiResponse, ImportResponse},
    CONFIGURATION, TACHI_IMPORT_URL, UPSERT_USER_ALL_API_ENCRYPTED,
};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

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

pub fn read_slice(buf: *const u8, len: usize) -> Result<Vec<u8>> {
    let mut slice = unsafe { std::slice::from_raw_parts(buf, len) };
    let mut ret = Vec::with_capacity(len);

    slice.read_to_end(&mut ret)?;

    Ok(ret)
}

pub fn read_maybe_compressed_buffer(buf: impl AsRef<[u8]>) -> Result<String> {
    let mut ret = String::new();

    let mut decoder = ZlibDecoder::new(buf.as_ref());
    let zlib_result = decoder.read_to_string(&mut ret);
    if zlib_result.is_ok() {
        return Ok(ret);
    }

    ret.clear();
    let result = buf.as_ref().read_to_string(&mut ret);
    if result.is_ok() {
        return Ok(ret);
    }

    Err(anyhow!(
        "Could not decode contents of buffer as both DEFLATE-compressed ({:#}) and plaintext ({:#}) UTF-8 string.",
        zlib_result.expect_err("This shouldn't happen, if Result was Ok the string should have been returned earlier."),
        result.expect_err("This shouldn't happen, if Result was Ok the string should have been returned earlier."),
    ))
}

/// Determine if we're looking at the UpsertUserAllApi endpoint,
/// which is the endpoint that contains our scores.
pub fn is_upsert_user_all_endpoint(endpoint: &str) -> bool {
    if endpoint == "UpsertUserAllApi" {
        return true;
    }

    if UPSERT_USER_ALL_API_ENCRYPTED
        .as_ref()
        .is_some_and(|v| v == endpoint)
    {
        return true;
    }

    false
}

/// Determine if it is an encrypted endpoint by checking if the endpoint
/// is exactly 32 characters long, and consists of all hex characters.
///
/// While this may trigger false positives, this should not happen as long
/// as CHUNITHM title APIs keep their `{method}{object}Api` endpoint
/// convention.
pub fn is_encrypted_endpoint(endpoint: &str) -> bool {
    if endpoint.len() != 32 {
        return false;
    }

    // Lazy way to check if all digits are hexadecimal
    if u128::from_str_radix(endpoint, 16).is_err() {
        return false;
    }

    true
}

pub fn decrypt_aes256_cbc(
    body: &mut [u8],
    key: impl AsRef<[u8]>,
    iv: impl AsRef<[u8]>,
) -> Result<Vec<u8>> {
    let cipher = Aes256CbcDec::new_from_slices(key.as_ref(), iv.as_ref())?;
    Ok(cipher
        .decrypt_padded_mut::<Pkcs7>(body)
        .map_err(|err| anyhow!(err))?
        .to_owned())
}

pub fn log_import(description: &str, import: ImportDocument) {
    info!(
        "{description} {} scores, {} sessions, {} errors",
        import.score_ids.len(),
        import.created_sessions.len(),
        import.errors.len()
    );

    for err in import.errors {
        error!("{}: {}", err.error_type, err.message);
    }
}

/// Executes a DIRECT-MANUAL import and logs some information on success.
///
/// ## Important
/// This function blocks until import has fully finished! It is best to call this in a separate thread.
pub fn execute_tachi_import(import: Import) -> Result<()> {
    let resp: TachiResponse<ImportResponse> =
        match request_tachi("POST", TACHI_IMPORT_URL.as_str(), Some(import)) {
            Err(err) => {
                return Err(anyhow!("Could not send scores to Tachi: {:#}", err));
            }
            Ok(resp) => resp,
        };

    let (body, description) = match resp {
        TachiResponse::Err(err) => {
            return Err(anyhow!(
                "Tachi API returned an error: {:#}",
                err.description
            ));
        }
        TachiResponse::Ok(resp) => (resp.body, resp.description),
    };

    let poll_url = match body {
        ImportResponse::Queued { url, import_id: _ } => {
            info!("Queued import for processing. Status URL: {}", url);
            url
        }
        ImportResponse::Finished(import) => {
            log_import(&description, import);
            return Ok(());
        }
    };

    loop {
        let resp: TachiResponse<ImportPollStatus> =
            match request_tachi("GET", &poll_url, None::<()>) {
                Ok(resp) => resp,
                Err(err) => {
                    error!("Could not poll import status: {:#}", err);
                    break;
                }
            };

        let (body, description) = match resp {
            TachiResponse::Ok(resp) => (resp.body, resp.description),
            TachiResponse::Err(err) => {
                return Err(anyhow!("Tachi API returned an error: {}", err.description));
            }
        };

        match body {
            ImportPollStatus::Completed { import } => {
                log_import(&description, import);
                return Ok(());
            }
            _ => {}
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    Ok(())
}
