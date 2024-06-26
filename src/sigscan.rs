use std::{ffi::CStr, slice};

use lightningscanner::{ScanMode, Scanner};
use log::{debug, error};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use snafu::prelude::Snafu;

#[derive(Debug)]
pub struct CryptoKeys {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub salt: Vec<u8>,
    pub iterations: u32,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Snafu)]
pub enum CryptoScanError {
    MissingSignature,
    NotEncrypted,
}

/// SAFETY: The caller ensures that `module_base` and `module_size` are valid.
pub unsafe fn is_network_encrypted(
    module_base: *const u8,
    module_size: usize,
) -> Result<bool, CryptoScanError> {
    let scan_mode = if is_x86_feature_detected!("avx2") {
        ScanMode::Avx2
    } else if is_x86_feature_detected!("sse4.2") {
        ScanMode::Sse42
    } else {
        ScanMode::Scalar
    };

    debug!("Using {scan_mode:?} for signature scanning");

    debug!("Scanning for the endpoint salt password");
    // b"?AVDeflate@projClient@@\x??\x??\x??\x??\x??\x??\x??\x??"
    // This is what the patchers are patching out when disabling encryption. This is
    // also where the endpoint salt password can be found.
    let scanner = Scanner::new("3F 41 56 44 65 66 6C 61 74 65 40 70 72 6F 6A 43 6C 69 65 6E 74 40 40 ?? ?? ?? ?? ?? ?? ?? ??");
    let result = scanner.find(Some(scan_mode), module_base, module_size);

    if !result.is_valid() {
        error!("Could not find the endpoint salt password");
        return Err(CryptoScanError::MissingSignature);
    }

    let crypto_config = *result.get_addr().wrapping_add(0x1B);

    if crypto_config == 0 {
        return Ok(false);
    }

    Ok(true)
}

/// SAFETY: The caller ensures that `module_base` and `module_size` are valid.
pub unsafe fn get_crypto_keys(
    module_base: *const u8,
    module_size: usize,
) -> Result<CryptoKeys, CryptoScanError> {
    let scan_mode = if is_x86_feature_detected!("avx2") {
        ScanMode::Avx2
    } else if is_x86_feature_detected!("sse4.2") {
        ScanMode::Sse42
    } else {
        ScanMode::Scalar
    };

    debug!("Using {scan_mode:?} for signature scanning");

    debug!("Scanning for the endpoint salt password");
    // b"?AVDeflate@projClient@@\x??\x??\x??\x??\x??\x??\x??\x??"
    // This is what the patchers are patching out when disabling encryption. This is
    // also where the endpoint salt password can be found.
    let scanner = Scanner::new("3F 41 56 44 65 66 6C 61 74 65 40 70 72 6F 6A 43 6C 69 65 6E 74 40 40 ?? ?? ?? ?? ?? ?? ?? ??");
    let result = scanner.find(Some(scan_mode), module_base, module_size);

    if !result.is_valid() {
        error!("Could not find the endpoint salt password");
        return Err(CryptoScanError::MissingSignature);
    }

    let crypto_config = *result.get_addr().wrapping_add(0x1B);

    if crypto_config == 0 {
        return Err(CryptoScanError::NotEncrypted);
    }

    let endpoint_salt_password_address = if crypto_config == *result.get_addr().wrapping_add(0x1F) {
        i32_from_ptr_le_bytes(result.get_addr().wrapping_add(0x23)) as *const i8
    } else {
        i32_from_ptr_le_bytes(result.get_addr().wrapping_add(0x1F)) as *const i8
    };

    let endpoint_salt_password = CStr::from_ptr(endpoint_salt_password_address);

    debug!(
        "Endpoint salt password: {} ({endpoint_salt_password_address:p})",
        endpoint_salt_password.to_string_lossy()
    );

    // Scanning for the call to [`PKCS5_PBKDF2_HMAC_SHA1`](https://www.openssl.org/docs/man3.2/man3/PKCS5_PBKDF2_HMAC_SHA1.html)
    // with saltlen=16, iter=31, keylen=8 to find the endpoint salt's salt
    let scanner = Scanner::new("52 6A 08 6A ?? 6A 10 68 ?? ?? ?? ?? 51 53 E8 ?? ?? ?? ??");
    let result = scanner.find(Some(scan_mode), module_base, module_size);

    if !result.is_valid() {
        return Err(CryptoScanError::MissingSignature);
    }

    let endpoint_salt_rounds = *result.get_addr().wrapping_add(0x04) as u32;
    let endpoint_salt_salt_address =
        i32_from_ptr_le_bytes(result.get_addr().wrapping_add(0x08)) as *const u8;
    let endpoint_salt_salt = slice::from_raw_parts(endpoint_salt_salt_address, 16);

    debug!(
        "Endpoint salt salt: {} ({endpoint_salt_salt_address:p})",
        faster_hex::hex_string(endpoint_salt_salt)
    );

    let mut endpoint_salt = vec![0u8; 8];
    pbkdf2_hmac::<Sha1>(
        endpoint_salt_password.to_bytes(),
        endpoint_salt_salt,
        endpoint_salt_rounds,
        &mut endpoint_salt,
    );

    debug!("Endpoint salt: {endpoint_salt:X?}");

    // Scanning for the call to [`PKCS5_PBKDF2_HMAC_SHA1`](https://www.openssl.org/docs/man3.2/man3/PKCS5_PBKDF2_HMAC_SHA1.html)
    // with saltlen=16, iter=??, keylen=32 to find the encryption key's salt
    let scanner = Scanner::new("50 6A 20 6A ?? 6A 10 2B CA 68 ?? ?? ?? ?? 51 55 E8 ?? ?? ?? ??");
    let result = scanner.find(Some(scan_mode), module_base, module_size);

    if !result.is_valid() {
        return Err(CryptoScanError::MissingSignature);
    }

    let encryption_key_rounds = *result.get_addr().wrapping_add(0x04) as u32;
    let encryption_key_salt_address =
        i32_from_ptr_le_bytes(result.get_addr().wrapping_add(0x0A)) as *const u8;
    let encryption_key_salt = slice::from_raw_parts(encryption_key_salt_address, 16);

    debug!(
        "Encryption key salt: {} ({encryption_key_salt_address:p})",
        faster_hex::hex_string(encryption_key_salt)
    );

    // b"?AVSystemInterface@projClient@@\x??\x??\x??\x??\x??\x??\x??\x??\x??\x??\x??\x??"
    let scanner = Scanner::new("3F 41 56 53 79 73 74 65 6D 49 6E 74 65 72 66 61 63 65 40 70 72 6F 6A 43 6C 69 65 6E 74 40 40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??");
    let result = scanner.find(Some(scan_mode), module_base, module_size);

    if !result.is_valid() {
        return Err(CryptoScanError::MissingSignature);
    }

    let encryption_key_password_address =
        i32_from_ptr_le_bytes(result.get_addr().wrapping_add(0x23)) as *const i8;
    let encryption_key_password = CStr::from_ptr(encryption_key_password_address);

    debug!(
        "Encryption key password: {} ({encryption_key_password_address:p})",
        encryption_key_password.to_string_lossy()
    );

    let mut encryption_key = vec![0u8; 32];
    pbkdf2_hmac::<Sha1>(
        encryption_key_password.to_bytes(),
        encryption_key_salt,
        encryption_key_rounds,
        &mut encryption_key,
    );

    for byte in encryption_key.iter_mut() {
        *byte = (*byte % 0x5E) + 0x21;
    }

    debug!("Encryption key: {encryption_key:X?}");

    // Encryption IV
    let scanner2 = Scanner::new("E8 ?? ?? ?? ?? F3 0F 7E 05 ?? ?? ?? ?? 6A 01");
    let result2 = scanner2.find(Some(scan_mode), module_base, module_size);

    let iv_addr = if result2.is_valid() {
        i32_from_ptr_le_bytes(result2.get_addr().wrapping_add(0x09)) as *const i8
    } else {
        let scanner1 = Scanner::new("F3 0F 7E 05 ?? ?? ?? ?? 8B 74 24 24 6A 01");
        let result1 = scanner1.find(Some(scan_mode), module_base, module_size);

        if !result1.is_valid() {
            return Err(CryptoScanError::MissingSignature);
        }

        i32_from_ptr_le_bytes(result1.get_addr().wrapping_add(0x04)) as *const i8
    };

    let iv = CStr::from_ptr(iv_addr).to_bytes().to_vec();

    debug!(
        "Encryption IV: {} ({iv_addr:p})",
        faster_hex::hex_string(&iv)
    );

    let scanner = Scanner::new("C7 86 ?? ?? ?? ?? ?? ?? ?? ?? 0F 8C ?? ?? ?? ?? 85 ED 0F 84 ?? ?? ?? ?? 85 DB 0F 84 ?? ?? ?? ??");
    let result = scanner.find(Some(scan_mode), module_base, module_size);

    if !result.is_valid() {
        return Err(CryptoScanError::MissingSignature);
    }

    let iterations = u32::from_le_bytes(from_raw_parts_const(result.get_addr().wrapping_add(0x06)));

    debug!("Iterations: {iterations}");

    Ok(CryptoKeys {
        key: encryption_key,
        iv,
        salt: endpoint_salt,
        iterations,
    })
}

unsafe fn from_raw_parts_const<const N: usize>(ptr: *const u8) -> [u8; N] {
    slice::from_raw_parts(ptr, N)
        .try_into()
        .expect("slice::from_raw_parts with len=N should convert to [u8; N]")
}

#[inline]
unsafe fn i32_from_ptr_le_bytes(ptr: *const u8) -> i32 {
    i32::from_le_bytes(from_raw_parts_const(ptr))
}
