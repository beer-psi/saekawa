mod defaults;
mod migrate;

use std::{collections::HashMap, path::PathBuf, str::FromStr};

use log::{info, warn};
use migrate::OldSaekawaConfig;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use url::Url;

use self::defaults::*;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SaekawaConfig {
    pub general: GeneralConfig,
    pub cards: HashMap<String, String>,
    pub tachi: TachiConfig,
}

#[derive(Snafu, Debug)]
pub enum ConfigLoadError {
    #[snafu(display(
        "Could not load or save configuration. Is the configuration format correct?"
    ))]
    ConfyError { source: confy::ConfyError },

    #[snafu(display("Could not migrate to new configuration format: {source:#?}"))]
    MigrationError { source: MigrationError },
}

#[derive(Snafu, Debug)]
pub enum MigrationError {
    #[snafu(display("Invalid Tachi base URL."))]
    InvalidTachiUrl { source: url::ParseError },
}

impl SaekawaConfig {
    pub fn load() -> Result<SaekawaConfig, ConfigLoadError> {
        let result = confy::load_path::<SaekawaConfig>("saekawa.toml");

        match result {
            Ok(_) => result.context(ConfySnafu),
            Err(_) => {
                warn!("Could not parse configuration, attempting to parse as old configuration...");
                let old_config =
                    confy::load_path::<OldSaekawaConfig>("saekawa.toml").context(ConfySnafu)?;

                info!("Successfully loaded as old configuration, migrating to new format...");
                let tachi_base_url = Url::parse(&old_config.tachi.base_url)
                    .context(InvalidTachiUrlSnafu)
                    .context(MigrationSnafu)?;
                let new_tachi_config = TachiConfig {
                    base_url: tachi_base_url,
                };

                let mut new_cards_config: HashMap<String, String> = HashMap::new();
                if old_config.cards.whitelist.is_empty() {
                    new_cards_config.insert("default".to_string(), old_config.tachi.api_key);
                } else {
                    for card in old_config.cards.whitelist {
                        new_cards_config.insert(card, old_config.tachi.api_key.clone());
                    }
                }

                let new_general_config = GeneralConfig {
                    export_class: old_config.general.export_class,
                    fail_over_lamp: old_config.general.fail_over_lamp,
                    timeout: old_config.general.timeout,
                    ..Default::default()
                };

                let new_config = SaekawaConfig {
                    general: new_general_config,
                    cards: new_cards_config,
                    tachi: new_tachi_config,
                };

                confy::store_path("saekawa.toml", new_config.clone()).context(ConfySnafu)?;

                Ok(new_config)
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GeneralConfig {
    #[serde(default = "default_true")]
    pub export_class: bool,

    #[serde(default = "default_false")]
    pub fail_over_lamp: bool,

    #[serde(default = "default_timeout")]
    pub timeout: u64,

    #[serde(default = "default_false")]
    pub auto_update: bool,

    #[serde(default = "default_failed_import_dir")]
    pub failed_import_dir: Option<PathBuf>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            export_class: true,
            fail_over_lamp: false,
            timeout: 5000,
            auto_update: true,
            failed_import_dir: PathBuf::from_str("failed_saekawa_imports").ok(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TachiConfig {
    #[serde(default = "default_tachi_url")]
    pub base_url: Url,
}

impl Default for TachiConfig {
    fn default() -> Self {
        Self {
            base_url: Url::parse("https://kamai.tachi.ac").unwrap(),
        }
    }
}
