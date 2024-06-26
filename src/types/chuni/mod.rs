mod music;
pub mod upsert;

use serde::{de, Deserialize};

pub use self::upsert::UpsertUserAllRequest;

fn deserialize_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: de::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BooleanishTypes {
        String(String),
        Bool(bool),
        Number(i32),
    }

    let s: BooleanishTypes = de::Deserialize::deserialize(deserializer)?;

    match s {
        BooleanishTypes::String(s) => match s.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(de::Error::unknown_variant(&s, &["true", "false"])),
        },
        BooleanishTypes::Bool(b) => Ok(b),
        BooleanishTypes::Number(n) => Ok(n > 0),
    }
}
