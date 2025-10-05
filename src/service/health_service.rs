use crate::model::EnStatus;
use crate::{
    error::ErrorMsg,
    facade::{self},
    model::{AppState, EnProductLine, EnTitle, UserClaims, WsUserLang},
    util::{get_message, validate_entity},
};
use axum::extract::State;
use axum::{
    Router,
    extract::{Json as JsonExtract, Path, Query},
    response::Json,
    routing::{delete, get, post, put},
};
use fluent_resmgr::ResourceManager;
use hyper::StatusCode;
use sqlx::{Acquire, Postgres, Transaction};

pub fn health_router() -> Router<AppState> {
    Router::new().route("/v1/health", get(get_health))
}

pub async fn get_health(State(state): State<AppState>) -> Result<Json<EnStatus>, ErrorMsg> {
    let up: EnStatus = EnStatus {
        status: String::from("pass"),
    };
    return Ok(Json(up));
}
