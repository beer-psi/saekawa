use std::io::Read;

use anyhow::{anyhow, Result};
use flate2::read::ZlibDecoder;

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
