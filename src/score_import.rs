use std::{fmt::Debug, fs::File, io, thread, time::Duration};

use log::{debug, error, info};
use rand::{rngs::ThreadRng, Rng};
use serde::{Deserialize, Serialize};
use snafu::{prelude::Snafu, ResultExt};

use crate::{
    config::SaekawaConfig,
    types::tachi::{
        api::{TachiFailureResponse, TachiResponse},
        api_returns::{ImportPollStatus, ImportResponse},
        batch_manual::BatchManualImport,
        documents::ImportDocument,
    },
};

const MAX_RETRY_COUNT: u32 = 3;
static SAEKAWA_USER_AGENT: &str = concat!("saekawa/", env!("CARGO_PKG_VERSION"));

#[derive(Snafu, Debug)]
pub enum ScoreImportError {
    #[snafu(display("Could not create import URL"))]
    InvalidImportUrl { source: url::ParseError },

    #[snafu(display("Tachi API returned an error: {}", response.description))]
    TachiError { response: TachiFailureResponse },

    #[snafu(display("Could not communicate with Tachi {max_retries} times."))]
    MaxRetriesExhausted { max_retries: u32 },

    #[snafu(display("Tachi returned an invalid response."))]
    InvalidTachiResponse { source: io::Error },

    #[snafu(display("Could not create backup batch manual file."))]
    FailedCreatingBackup { source: io::Error },

    #[snafu(display("Could not write backup batch manual file."))]
    FailedWritingBackup { source: serde_json::Error },
}

/// This function blocks until it has completed, which may take a long time
/// depending on the user's internet connection with Tachi. It's best to call
/// this in a separate thread.
pub fn execute_score_import(
    import: BatchManualImport,
    access_code: &str,
    api_key: &str,
    config: &SaekawaConfig,
) -> Result<(), ScoreImportError> {
    // Checking if there's actually anything to import before continuing on
    if import.scores.is_empty()
        && (import.classes.is_none()
            || import
                .classes
                .as_ref()
                .is_some_and(|c| c.dan.is_none() && c.emblem.is_none()))
    {
        return Ok(());
    }

    let import_url = config
        .tachi
        .base_url
        .join("/ir/direct-manual/import")
        .context(InvalidImportUrlSnafu)?
        .to_string();
    let client = saekawa_client(config);
    let response = match request_tachi::<_, ImportResponse>(
        &client,
        "POST",
        &import_url,
        &api_key,
        Some(&import),
    ) {
        Ok(r) => r,
        Err(ScoreImportError::MaxRetriesExhausted { max_retries }) => {
            error!("Could not reach Tachi after {max_retries} attempts.");

            let Some(d) = &config.general.failed_import_dir else {
                return Err(ScoreImportError::MaxRetriesExhausted { max_retries });
            };

            info!("Saving batch manual JSON to configured failed import directory for later import.");
            
            let current_time = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
            let failed_import_filename =
                d.join(format!("saekawa_{}_{}.json", access_code, current_time));

            {
                let file = File::create(&failed_import_filename).context(FailedCreatingBackupSnafu)?;
                serde_json::to_writer_pretty(file, &import).context(FailedWritingBackupSnafu)?;
            }

            info!("Saved batch manual JSON to {}", failed_import_filename.to_string_lossy());
            
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    let response = match response {
        TachiResponse::Ok(r) => r,
        TachiResponse::Err(e) => return Err(ScoreImportError::TachiError { response: e }),
    };

    match response.body {
        ImportResponse::Deferred(d) => {
            info!("Import was queued for processing. Poll URL: {}", d.url);
            poll_deferred_import(&client, &api_key, &d.url);
            return Ok(());
        }
        ImportResponse::Completed(d) => {
            log_tachi_import(&response.description, &d);
            return Ok(());
        }
    }
}

fn saekawa_client(config: &SaekawaConfig) -> ureq::Agent {
    ureq::builder()
        .timeout(Duration::from_millis(config.general.timeout))
        .user_agent(SAEKAWA_USER_AGENT)
        .build()
}

fn exponential_backoff(rand: &mut ThreadRng, attempt: u32) -> u64 {
    // attempt | backoff
    // 0       | 2-4 seconds
    // 1       | 8-16 seconds
    // 2       | 32-64 seconds
    return rand.gen_range(500..=1000) * 4_u64.pow(attempt + 1);
}

fn request_tachi<T, R>(
    client: &ureq::Agent,
    method: &str,
    url: &str,
    api_key: &str,
    body: Option<T>,
) -> Result<TachiResponse<R>, ScoreImportError>
where
    T: Serialize + Debug,
    R: for<'de> Deserialize<'de> + Debug,
{
    let auth_header = format!("Bearer {}", api_key);
    let mut rand = rand::thread_rng();

    for attempt in 0..MAX_RETRY_COUNT {
        debug!(
            "Requesting Tachi, attempt {}/{MAX_RETRY_COUNT}",
            attempt + 1
        );

        let request = client
            .request(method, url)
            .set("Authorization", &auth_header);
        let response = if let Some(ref body) = body {
            request.send_json(body)
        } else {
            request.call()
        };
        let response = match response {
            Ok(r) => r,
            Err(ureq::Error::Transport(e)) => {
                error!("Could not reach Tachi API. Is your network up or are they having issues?.");

                if let Some(m) = e.message() {
                    error!("Detailed error message: {}", m);
                }

                if attempt != MAX_RETRY_COUNT - 1 {
                    let wait_time = exponential_backoff(&mut rand, attempt);

                    info!("Waiting for {wait_time}ms before trying again...");
                    thread::sleep(Duration::from_millis(wait_time));
                    continue;
                }

                break;
            }
            Err(ureq::Error::Status(code, response)) => {
                if code >= 500 {
                    error!("Tachi is having a server error. Response code was {code}.");

                    if let Ok(s) = response.into_string() {
                        error!("Response from Tachi: {s}");
                    } else {
                        error!("No response could be read.");
                    }

                    if attempt != MAX_RETRY_COUNT - 1 {
                        let wait_time = exponential_backoff(&mut rand, attempt);

                        info!("Waiting for {wait_time}ms before trying again...");
                        thread::sleep(Duration::from_millis(wait_time));
                        continue;
                    }

                    break;
                }

                response
            }
        };

        return response
            .into_json::<TachiResponse<R>>()
            .context(InvalidTachiResponseSnafu);
    }

    return Err(ScoreImportError::MaxRetriesExhausted {
        max_retries: MAX_RETRY_COUNT,
    });
}

fn log_tachi_import(description: &str, import: &ImportDocument) {
    info!(
        "{description} {} scores, {} sessions, {} errors",
        import.score_ids.len(),
        import.created_sessions.len(),
        import.errors.len()
    );

    for err in &import.errors {
        error!("{}: {}", err.error_type, err.message);
    }
}

fn poll_deferred_import(client: &ureq::Agent, api_key: &str, poll_url: &str) {
    loop {
        let resp = match request_tachi::<_, ImportPollStatus>(
            &client, "GET", &poll_url, &api_key, None::<()>,
        ) {
            Ok(r) => r,
            Err(e) => {
                error!("Could not poll import status. While Tachi has received the score, Saekawa cannot make any guarantees about its success. Detailed error: {e:#}");
                return;
            }
        };

        let resp = match resp {
            TachiResponse::Ok(r) => r,
            TachiResponse::Err(e) => {
                error!("Tachi API returned an error: {}", e.description);
                return;
            }
        };

        match resp.body {
            ImportPollStatus::Completed { import } => {
                log_tachi_import(&resp.description, &import);
                return;
            }
            _ => {}
        }

        thread::sleep(Duration::from_secs(1));
    }
}
