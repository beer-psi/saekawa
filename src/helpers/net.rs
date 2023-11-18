use std::fmt::Debug;

use anyhow::{anyhow, Result};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};

use crate::{
    types::tachi::{Import, ImportDocument, ImportPollStatus, ImportResponse, TachiResponse},
    CONFIGURATION, TACHI_IMPORT_URL,
};

pub fn request_agent() -> ureq::Agent {
    let timeout = CONFIGURATION.general.timeout;
    let timeout = if timeout > 10000 { 10000 } else { timeout };

    ureq::builder()
        .timeout(std::time::Duration::from_millis(timeout))
        .build()
}

fn request<T>(
    method: impl AsRef<str>,
    url: impl AsRef<str>,
    body: Option<T>,
) -> Result<ureq::Response>
where
    T: Serialize + Debug,
{
    let agent = request_agent();

    let method = method.as_ref();
    let url = url.as_ref();
    debug!("{} request to {} with body: {:#?}", method, url, body);

    let authorization = format!("Bearer {}", CONFIGURATION.tachi.api_key);
    let request = agent
        .request(method, url)
        .set("Authorization", authorization.as_str());
    let response = match body {
        Some(body) => request.send_json(body),
        None => request.call(),
    }
    .map_err(|err| anyhow::anyhow!("Could not reach Tachi API: {:#}", err))?;

    Ok(response)
}

pub fn request_tachi<T, R>(
    method: impl AsRef<str>,
    url: impl AsRef<str>,
    body: Option<T>,
) -> Result<R>
where
    T: Serialize + Debug,
    R: for<'de> Deserialize<'de> + Debug,
{
    let response = request(method, url, body)?;
    let response = response.into_json()?;
    debug!("Tachi API response: {:#?}", response);

    Ok(response)
}

fn log_import(description: &str, import: ImportDocument) {
    info!(
        "{description} {} scores, {} sessions, {} errors",
        import.score_ids.len(),
        import.created_sessions.len(),
        import.errors.len()
    );

    for err in import.errors {
        error!("{}: {}", err.error_type, err.message);
    }
}

/// Executes a DIRECT-MANUAL import and logs some information on success.
///
/// ## Important
/// This function blocks until import has fully finished! It is best to call this in a separate thread.
pub fn execute_tachi_import(import: Import) -> Result<()> {
    let resp: TachiResponse<ImportResponse> =
        match request_tachi("POST", TACHI_IMPORT_URL.as_str(), Some(import)) {
            Err(err) => {
                return Err(anyhow!("Could not send scores to Tachi: {:#}", err));
            }
            Ok(resp) => resp,
        };

    let (body, description) = match resp {
        TachiResponse::Err(err) => {
            return Err(anyhow!(
                "Tachi API returned an error: {:#}",
                err.description
            ));
        }
        TachiResponse::Ok(resp) => (resp.body, resp.description),
    };

    let poll_url = match body {
        ImportResponse::Queued { url, import_id: _ } => {
            info!("Queued import for processing. Status URL: {}", url);
            url
        }
        ImportResponse::Finished(import) => {
            log_import(&description, import);
            return Ok(());
        }
    };

    loop {
        let resp: TachiResponse<ImportPollStatus> =
            match request_tachi("GET", &poll_url, None::<()>) {
                Ok(resp) => resp,
                Err(err) => {
                    error!("Could not poll import status: {:#}", err);
                    break;
                }
            };

        let (body, description) = match resp {
            TachiResponse::Ok(resp) => (resp.body, resp.description),
            TachiResponse::Err(err) => {
                return Err(anyhow!("Tachi API returned an error: {}", err.description));
            }
        };

        match body {
            ImportPollStatus::Completed { import } => {
                log_import(&description, import);
                return Ok(());
            }
            _ => {}
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    Ok(())
}
