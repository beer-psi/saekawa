use std::{io, num::ParseIntError, sync::OnceLock};

use ini::Ini;
use log::{debug, info};
use serde::Deserialize;
use snafu::{prelude::Snafu, ResultExt};

use crate::{
    config::{ConfigLoadError, SaekawaConfig},
    helpers::winapi_ext::LibraryHandle,
    hooks,
};

#[cfg(feature = "autoupdate")]
use log::error;

#[cfg(feature = "autoupdate")]
use crate::updater::self_update;

#[derive(Debug, Snafu)]
pub enum SaekawaError {
    #[snafu(display("Could not load configuration: {source:#?}"))]
    ConfigError { source: ConfigLoadError },

    #[snafu(display("No cards were configured in the [cards] section. There is nothing to export to. Add tokens under the cards section with the format `\"access_code\" = \"tachi_api_key\"`. If you wish to export scores from all cards, use `default` in place of an access code."))]
    NoCardsError,

    #[snafu(display("An error occured hooking the underlying functions: {source:#?}"))]
    HookError { source: hooks::HookError },

    #[snafu(display("The game version specified in project.conf is not a number."))]
    InvalidVersion { source: ParseIntError },

    #[snafu(display("An error occured parsing project.conf: {source:#?}"))]
    IniError { source: ini::Error },

    #[snafu(display("The configured path for failed import exists and is not a directory."))]
    FailedImportNotDir,

    #[snafu(display("Could not create the configured directory for failed imports: {source:#?}"))]
    FailedCreatingFailedImportDir { source: io::Error },
}

#[derive(Debug, Clone, Deserialize)]
pub struct GameInformation {
    pub game_id: String,
    pub major: u16,
    pub minor: u8,
    pub build: u8,
}

pub static CONFIG: OnceLock<SaekawaConfig> = OnceLock::new();

#[cfg_attr(not(feature = "autoupdate"), allow(unused_variables))]
pub fn hook_init(library_handle: LibraryHandle) -> Result<(), SaekawaError> {
    debug!("Reading hook configuration");
    let config = SaekawaConfig::load().context(ConfigSnafu)?;

    #[cfg(feature = "autoupdate")]
    {
        if config.general.auto_update {
            match self_update(&library_handle) {
                Ok(should_reboot) => {
                    if should_reboot {
                        info!("Self-update successful. Reloading into new hook...");
                        library_handle.free_and_exit_thread(1);
                    }
                }
                Err(e) => {
                    error!("Self-update failed: {e:#}");
                }
            }
        }
    }

    if config.cards.is_empty() {
        return Err(SaekawaError::NoCardsError);
    }

    info!("Loaded API keys for {} access code(s).", config.cards.len());

    if let Some(d) = &config.general.failed_import_dir {
        if d.exists() && !d.is_dir() {
            return Err(SaekawaError::FailedImportNotDir);
        }

        if !d.exists() {
            std::fs::create_dir_all(d).context(FailedCreatingFailedImportDirSnafu)?;
        }
    }

    debug!("Reading version information from project.conf");
    let info = get_project_conf()?;

    info!(
        "Running on {} {}.{:0>2}.{:0>2}",
        info.game_id, info.major, info.minor, info.build
    );

    CONFIG
        .set(config)
        .expect("OnceLock shouldn't be initialized.");

    hooks::attach_all().context(HookSnafu)?;
    hooks::enable_all().context(HookSnafu)?;

    info!("Hooks enabled.");

    Ok(())
}

pub fn hook_release() -> Result<(), SaekawaError> {
    hooks::disable_all().context(HookSnafu)?;

    info!("Hooks disabled.");

    Ok(())
}

fn get_project_conf() -> Result<GameInformation, SaekawaError> {
    let project_conf = Ini::load_from_file("./project.conf").context(IniSnafu)?;
    let major_version = &project_conf["Version"]["VerMajor"];
    let minor_version = &project_conf["Version"]["VerMinor"];
    let build_version = &project_conf["Version"]["VerRelease"];
    let game_id = &project_conf["Project"]["GameID"];

    Ok(GameInformation {
        game_id: game_id.to_string(),
        major: major_version.parse::<u16>().context(InvalidVersionSnafu)?,
        minor: minor_version.parse::<u8>().context(InvalidVersionSnafu)?,
        build: build_version.parse::<u8>().context(InvalidVersionSnafu)?,
    })
}
