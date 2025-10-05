use crate::{
    error::ErrorMsg,
    facade::{self, select_product_line_by_id},
    model::{AppState, EnProductLine, EnProductLineProducts, EnTitle, UserClaims, WsUserLang},
};
use axum::extract::State;
use axum::{
    Router,
    extract::{Json as JsonExtract, Path, Query},
    response::Json,
    routing::{delete, get, post, put},
};
use sqlx::{Postgres, Transaction};


pub fn product_line_router() -> Router<AppState> {
    Router::new()
        .route("/v1/product_lines/{id}", delete(delete_product_line))
        .route("/v1/product_lines", get(get_product_lines))
        .route("/v1/product_lines", post(post_product_line))
        .route("/v1/product_lines/{id}", put(put_product_lines))
}

pub async fn get_product_lines(
    State(state): State<AppState>,
) -> Result<Json<Vec<EnProductLineProducts>>, ErrorMsg> {
    let result: Vec<EnProductLineProducts> = facade::select_product_lines(&state.pool).await?;
    Ok(Json(result))
}

pub async fn put_product_lines(
    State(state): State<AppState>,
    Path(id): Path<i16>,
    Query(lang): Query<WsUserLang>,
    claims: UserClaims,
    JsonExtract(product_line): JsonExtract<EnTitle>,
) -> Result<(), ErrorMsg> {
    if !claims.security {
        return Err(crate::error::unauthorized_error(&lang));
    }

    let mut tx: Transaction<'static, Postgres> = state.pool.begin().await?;
    facade::update_product_line(&mut tx, &product_line, id).await?;
    tx.commit().await?;

    Ok(())
}

pub async fn post_product_line(
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
    let id: i16 = facade::insert_product_line(&mut tx, &product_line).await?;
    tx.commit().await?;

    let mut tx: Transaction<'static, Postgres> = state.pool.begin().await?;
    Ok(Json(select_product_line_by_id(&mut tx, &id).await?))
}


pub async fn delete_product_line(
    State(state): State<AppState>,
    Path(pl_id): Path<i16>,
    claims: UserClaims,
    Query(lang): Query<WsUserLang>,
) -> Result<(), ErrorMsg> {
    if !claims.security {
        return Err(crate::error::unauthorized_error(&lang));
    }

    let mut tx: Transaction<'static, Postgres> = state.pool.begin().await?;
    crate::facade::delete_by_id(&mut tx, "product_line", pl_id).await?;
    tx.commit().await?;

    Ok(())
}
