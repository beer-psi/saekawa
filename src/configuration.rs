use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Configuration {
    pub general: GeneralConfiguration,

    pub cards: CardsConfiguration,

    #[serde(default)]
    pub crypto: CryptoConfiguration,

    pub tachi: TachiConfiguration,
}

impl Configuration {
    pub fn load() -> Result<Self> {
        if !Path::new("saekawa.toml").exists() {
            File::create("saekawa.toml")
                .and_then(|mut file| file.write_all(include_bytes!("../res/saekawa.toml")))
                .map_err(|err| anyhow::anyhow!("Could not create default config file: {}", err))?;
        }

        confy::load_path("saekawa.toml")
            .map_err(|err| anyhow::anyhow!("Could not load config: {}", err))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeneralConfiguration {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default = "default_true")]
    pub export_class: bool,

    #[serde(default = "default_false")]
    pub fail_over_lamp: bool,

    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_timeout() -> u64 {
    3000
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CardsConfiguration {
    #[serde(default)]
    pub whitelist: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CryptoConfiguration {
    #[serde(with = "faster_hex::nopfx_lowercase")]
    pub key: Vec<u8>,

    #[serde(with = "faster_hex::nopfx_lowercase")]
    pub iv: Vec<u8>,

    #[serde(with = "faster_hex::nopfx_lowercase")]
    pub salt: Vec<u8>,

    #[serde(default = "default_iterations")]
    pub iterations: u32,
}

fn default_iterations() -> u32 {
    70
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TachiConfiguration {
    pub base_url: String,
    pub status: String,
    pub import: String,
    pub api_key: String,
}
