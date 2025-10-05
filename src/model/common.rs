use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Pool, Postgres};
use validator::Validate;

#[derive(Clone /*, FromRef*/)]
pub struct AppState {
    pub(crate) pool: Pool<Postgres>,
    //pub(crate) claims: ClaimsTournament
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct WsSmallId {
    pub id: i16,
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct WsId {
    pub id: i32,
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct WsBigId {
    pub id: i64,
}

#[derive(Serialize, Deserialize)]
pub struct QueryLangFromToDateSportId {
    pub lang: String,
    pub from_date: chrono::NaiveDate,
    pub to_date: chrono::NaiveDate,
    pub sport_id: i16,
}

#[derive(Serialize, Deserialize)]
pub struct QueryLangId {
    pub lang: String,
    pub id: i16,
}

#[derive(Serialize, Deserialize, Validate)]
pub struct QueryLangLastname {
    pub lang: String,
    #[validate(length(min = 1, max = 200, message = "field-title-length"))]
    pub lastname: String,
}

#[derive(Serialize, Deserialize)]
pub struct WsUserLang {
    pub lang: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserClaims {
    pub(crate) sub: String,
    pub(crate) security: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimsZit {
    pub sub: String,
    pub exp: usize,
    //#[serde(deserialize_with = "urn:zitadel:iam:org:project:roles")]
    #[serde(alias = "urn:zitadel:iam:org:project:roles", alias = "KUBE")]
    pub roles: Option<HashMap<String, HashMap<String, String>>>,
}

#[derive(Serialize, Deserialize)]
pub struct ZitOauthKeys {
    pub keys: Vec<ZitOauthKey>,
}

#[derive(Serialize, Deserialize)]
pub struct ZitOauthKey {
    #[serde(alias = "use")]
    pub usage: String,
    pub kty: String,
    pub kid: String,
    pub alg: String,
    pub n: String,
    pub e: String,
}

#[derive(Serialize, Deserialize)]
pub struct EnTitle {
    pub title: String,
}

#[derive(Serialize, Deserialize)]
pub struct EnStatus {
    pub status: String,
}
