use crate::{
    error::ErrorMsg,
    facade::{self, select_product_line_by_id},
    model::{
        AppState, EnProductLine, EnProductLineProducts, EnTitle, RePackage, UserClaims, WsUserLang,
    },
};
use axum::extract::State;
use axum::{
    Router,
    extract::{Json as JsonExtract, Path, Query},
    response::Json,
    routing::{delete, get, post, put},
};
use sqlx::{Postgres, Transaction};

pub fn package_version_router() -> Router<AppState> {
    Router::new().route(
        "/api/v1/product_lines/{id}/products/{id}/packages/{id}/versions/{id}",
        get(get_package_version),
    )
}

/**
 * Get the package_version and his package.
 */
pub async fn get_package_version(
    State(state): State<AppState>,
    Path((_pl_id, _p_id, _pkg_id, package_version_id)): Path<(i16, i32, i32, i64)>,
) -> Result<Json<Option<RePackage>>, ErrorMsg> {
    let mut tx: Transaction<'static, Postgres> = state.pool.begin().await?;
    let result: Option<RePackage> =
        facade::select_package_version_by_id(&mut tx, &package_version_id).await?;
    tx.commit().await?;
    Ok(Json(result))
}
