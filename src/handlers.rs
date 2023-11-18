use std::{fmt::Debug, sync::atomic::Ordering};

use log::{debug, error, info};
use serde::de::DeserializeOwned;

use crate::{
    helpers::execute_tachi_import, saekawa::GAME_MAJOR_VERSION, types::tachi::ToTachiImport,
    CONFIGURATION,
};

pub fn score_handler<T>(body: String, guard: impl Fn(&T) -> bool)
where
    T: Debug + DeserializeOwned + ToTachiImport,
{
    let data = match serde_json::from_str::<T>(body.as_ref()) {
        Ok(req) => req,
        Err(err) => {
            error!("Could not parse request body: {:#}", err);
            return;
        }
    };

    debug!("parsed request body: {:#?}", data);

    if !guard(&data) {
        return;
    }

    let import = data.to_tachi_import(
        GAME_MAJOR_VERSION.load(Ordering::SeqCst),
        CONFIGURATION.general.export_class,
        CONFIGURATION.general.fail_over_lamp,
    );

    if import.scores.is_empty() {
        if import.classes.is_none() {
            return;
        }

        if import
            .classes
            .clone()
            .is_some_and(|v| v.dan.is_none() && v.emblem.is_none())
        {
            return;
        }
    }

    info!(
        "Submitting {} scores from {} {}",
        import.scores.len(),
        data.displayed_id_type(),
        data.displayed_id(),
    );

    if let Err(err) = execute_tachi_import(import) {
        error!("{:#}", err);
    }
}
