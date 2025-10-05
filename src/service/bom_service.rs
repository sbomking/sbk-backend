use crate::{
    error::ErrorMsg,
    facade::{self, select_product_line_by_id},
    model::{AppState, EnProduct, EnProductLine, EnTitle, UserClaims, WsUserLang},
    util::{get_message, validate_entity},
};
use axum::extract::State;
use axum::{
    Router,
    extract::{Json as JsonExtract, Path, Query},
    response::Json,
    routing::{delete, get, post, put},
};
use hyper::StatusCode;
use sqlx::{Postgres, Transaction};

pub fn bom_router() -> Router<AppState> {
    Router::new().route("/v1/product_lines/{id}/products/{id}/bom", post(post_bom))
}

/**
 * Store a BOM to S3.
 * Update table.
 * Scan and return result.
 *
 * Add input param. Ex scan option true or false.
 */
pub async fn post_bom(
    State(state): State<AppState>,
    Query(lang): Query<WsUserLang>,
    claims: UserClaims,
    JsonExtract(product_line): JsonExtract<EnTitle>,
) -> Result<Json<EnProductLine>, ErrorMsg> {
    if !claims.security {
        return Err(crate::error::unauthorized_error(&lang));
    }

    /*
    match validate_entity(&product_line, &lang.lang).first() {
        Some(validation_error) => {
            return Err(ErrorMsg {
                title: validation_error.to_string(),
                status: StatusCode::CONFLICT.as_u16(),
                _type: None,
                detail: None,
                instance: None,
                code: None,
                errors: vec![],
            });
        }
        None => {}
    };
    */

    let mut tx: Transaction<'static, Postgres> = state.pool.begin().await?;
    let id: i16 = facade::insert_product(&mut tx, &product_line).await?;
    tx.commit().await?;

    let mut tx: Transaction<'static, Postgres> = state.pool.begin().await?;
    Ok(Json(select_product_line_by_id(&mut tx, &id).await?))
}
