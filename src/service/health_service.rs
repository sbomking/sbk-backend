use crate::model::EnStatus;
use crate::{
    error::ErrorMsg,
    model::AppState,
};
use axum::extract::State;
use axum::{
    Router,
    response::Json,
    routing::get,
};

pub fn health_router() -> Router<AppState> {
    Router::new().route("/v1/health", get(get_health))
}

pub async fn get_health(State(state): State<AppState>) -> Result<Json<EnStatus>, ErrorMsg> {
    let up: EnStatus = EnStatus {
        status: String::from("pass"),
    };
    Ok(Json(up))
}
