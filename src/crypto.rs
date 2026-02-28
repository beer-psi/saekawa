use log::warn;
use serde::{Deserialize, Serialize};

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use pbkdf2::pbkdf2_hmac_array;
use sha1::Sha1;
use snafu::prelude::Snafu;

use crate::{config::SaekawaConfig, saekawa::GameInformation};

#[derive(Debug, Clone)]
pub struct GameCryptoInformation {
    pub upsert_user_all_endpoint: String,
    pub upsert_user_all_hashed_endpoint: Option<String>,
    pub key: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MinorVersion {
    Single(u8),
    Range((u8, u8)),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoKeys {
    pub game_id: String,
    pub major: u16,
    pub minor: MinorVersion,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub salt: Vec<u8>,
    pub iterations: u32,
}

impl CryptoKeys {
    fn is_compatible_with(&self, info: &GameInformation) -> bool {
        match self.minor {
            MinorVersion::Single(minor) => {
                self.major == info.major && minor == info.minor && self.game_id == info.game_id
            }
            MinorVersion::Range((start, end)) => {
                self.major == info.major
                    && start <= info.minor
                    && info.minor <= end
                    && self.game_id == info.game_id
            }
        }
    }
}

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Snafu, Debug)]
pub enum DecryptError {
    InvalidLength,
    UnpadError,
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

pub fn get_game_crypto_information(
    config: &SaekawaConfig,
    info: &GameInformation,
) -> GameCryptoInformation {
    let endpoint = if info.game_id == "SDGS" {
        if info.minor < 10 {
            "UpsertUserAllApiExp"
        } else {
            "UpsertUserAllApiC3Exp"
        }
    } else {
        "UpsertUserAllApi"
    };
    let crypto_keys: Vec<CryptoKeys> =
        serde_json::from_str(obfstr::obfstr!(include_str!("../res/keys.json")))
            .expect("can deserialize key list");
    let Some(keys) = config
        .keys
        .iter()
        .chain(&crypto_keys)
        .find(|k| k.is_compatible_with(info))
    else {
        warn!(
            "Encryption is not supported for {} {}.{:0>2}.{:0>2}. Please enable the \"No encryption\" patch on a patcher, or add encryption keys in the configuration file.",
            info.game_id, info.major, info.minor, info.build
        );

        return GameCryptoInformation {
            upsert_user_all_endpoint: endpoint.to_string(),
            upsert_user_all_hashed_endpoint: None,
            key: None,
            iv: None,
        };
    };

    // For some reason, CHUNITHM SUPERSTAR/SUPERSTAR+ forgot to add "Exp" when
    // hashing the endpoint.
    let endpoint_password = if info.game_id == "SDGS" && info.minor < 10 {
        "UpsertUserAllApi"
    } else {
        endpoint
    };

    GameCryptoInformation {
        upsert_user_all_endpoint: endpoint.to_string(),
        upsert_user_all_hashed_endpoint: Some(hash_endpoint(
            endpoint_password,
            &keys.salt,
            keys.iterations,
        )),
        key: Some(keys.key.clone()),
        iv: Some(keys.iv.clone()),
    }
}
