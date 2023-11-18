use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use anyhow::{anyhow, Result};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

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
