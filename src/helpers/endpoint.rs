use log::debug;
use pbkdf2::pbkdf2_hmac_array;
use sha1::Sha1;

use crate::CONFIGURATION;

pub fn is_endpoint(
    endpoint: &str,
    unencrypted_variant: &str,
    encrypted_variant: &Option<String>,
) -> bool {
    if endpoint == unencrypted_variant {
        return true;
    }

    if encrypted_variant.as_ref().is_some_and(|v| v == endpoint) {
        return true;
    }

    return false;
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

pub fn hash_endpoint(endpoint: &str) -> Option<String> {
    if CONFIGURATION.crypto.salt.is_empty() {
        return None;
    }

    let key_bytes = pbkdf2_hmac_array::<Sha1, 16>(
        endpoint.as_bytes(),
        &CONFIGURATION.crypto.salt,
        CONFIGURATION.crypto.iterations,
    );

    let key = faster_hex::hex_string(&key_bytes);

    debug!("Running with encryption support: {endpoint} maps to {key}");

    Some(key)
}
