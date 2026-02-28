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

/// Module for parsing CHUNITHM datetimes (2006-01-02 03:04:05) into [`jiff::Zoned`]
/// values at Asia/Tokyo.
mod serde_chuni_date {
    use serde::{de, ser};

    const DT_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

    #[derive(Debug)]
    struct UserPlayDateVisitor;

    pub fn serialize<S>(dt: &jiff::Zoned, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&dt.strftime(DT_FORMAT).to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<jiff::Zoned, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_str(UserPlayDateVisitor)
    }

    impl<'de> de::Visitor<'de> for UserPlayDateVisitor {
        type Value = jiff::Zoned;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(formatter, "a string in the format of \"{}\"", DT_FORMAT)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            jiff::civil::DateTime::strptime(DT_FORMAT, v)
                .map(|dt| dt.in_tz("Asia/Tokyo").map_err(E::custom))
                .map_err(E::custom)
                .flatten()
        }
    }
}
