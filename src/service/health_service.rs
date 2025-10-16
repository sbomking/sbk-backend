use crate::model::EnStatus;
use crate::{
    error::ErrorMsg,
    model::AppState,
};
use axum::{
    Router,
    response::Json,
    routing::get,
};

pub fn health_router() -> Router<AppState> {
    Router::new().route("/v1/health", get(get_health))
}

//#[utoipa::path(get, path = "/v1/health", responses((status = OK, body = EnStatus)))]
pub async fn get_health() -> Result<Json<EnStatus>, ErrorMsg> {
    let up: EnStatus = EnStatus {
        status: String::from("pass"),
    };
    Ok(Json(up))
}
