use serde::{de, Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub enum TachiResponse<T> {
    Ok(TachiSuccessResponse<T>),
    Err(TachiFailureResponse),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TachiSuccessResponse<T> {
    pub description: String,
    pub body: T,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TachiFailureResponse {
    pub description: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TachiApiPermission {
    CustomiseProfile,
    CustomiseScore,
    CustomiseSession,
    DeleteScore,
    ManageChallenges,
    ManageRivals,
    ManageTargets,
    SubmitScore,
}

impl<'de, T> Deserialize<'de> for TachiResponse<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut map = Map::deserialize(deserializer)?;
        let success = map
            .remove("success")
            .ok_or_else(|| de::Error::missing_field("success"))
            .map(Deserialize::deserialize)?
            .map_err(de::Error::custom)?;
        let rest = Value::Object(map);

        if success {
            TachiSuccessResponse::deserialize(rest)
                .map(TachiResponse::Ok)
                .map_err(de::Error::custom)
        } else {
            TachiFailureResponse::deserialize(rest)
                .map(TachiResponse::Err)
                .map_err(de::Error::custom)
        }
    }
}
