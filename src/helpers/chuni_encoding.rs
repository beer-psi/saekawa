use std::io::{self, Read};

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use flate2::read::ZlibDecoder;
use pbkdf2::pbkdf2_hmac_array;
use sha1::Sha1;
use snafu::prelude::Snafu;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Snafu, Debug)]
pub enum DecryptError {
    InvalidLength,
    UnpadError,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct MaybeDecompressError {
    pub zlib_error: io::Error,
    pub raw_error: io::Error,
}

pub fn hash_endpoint(endpoint: impl AsRef<str>, salt: impl AsRef<[u8]>, rounds: u32) -> String {
    let key_bytes =
        pbkdf2_hmac_array::<Sha1, 16>(endpoint.as_ref().as_bytes(), salt.as_ref(), rounds);

    faster_hex::hex_string(&key_bytes)
}

pub fn decrypt_aes256_cbc(
    body: &mut [u8],
    key: impl AsRef<[u8]>,
    iv: impl AsRef<[u8]>,
) -> Result<Vec<u8>, DecryptError> {
    let cipher = Aes256CbcDec::new_from_slices(key.as_ref(), iv.as_ref())
        .map_err(|_| DecryptError::InvalidLength)?;

    Ok(cipher
        .decrypt_padded_mut::<Pkcs7>(body)
        .map_err(|_| DecryptError::UnpadError)?
        .to_owned())
}

pub fn maybe_decompress_buffer(buf: impl AsRef<[u8]>) -> Result<String, MaybeDecompressError> {
    let mut ret = String::with_capacity(buf.as_ref().len() * 2);

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

    Err(MaybeDecompressError {
        zlib_error: zlib_result.expect_err("must be Err if reached here"),
        raw_error: result.expect_err("must be Err if reached here"),
    })
}
