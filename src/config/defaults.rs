use std::{path::PathBuf, str::FromStr};

use url::Url;

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_false() -> bool {
    false
}

pub(super) fn default_timeout() -> u64 {
    5000
}

pub(super) fn default_tachi_url() -> Url {
    Url::parse("https://kamai.tachi.ac").unwrap()
}

pub(super) fn default_failed_import_dir() -> Option<PathBuf> {
    PathBuf::from_str("failed_saekawa_imports").ok()
}
