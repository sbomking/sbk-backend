use crate::{
    error::ErrorMsg,
    facade::{self, select_product_line_by_id},
    model::{AppState, EnProduct, EnProductLine, EnTitle, UserClaims, WsUserLang},
};
use axum::extract::State;
use axum::{
    Router,
    extract::{Json as JsonExtract, Path, Query},
    response::Json,
    routing::{delete, get, post, put},
};
use sqlx::{Postgres, Transaction};

pub fn product_router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/product_lines/{id}/products/{id}",
            delete(delete_product),
        )
        .route("/v1/product_lines/{id}/products", get(get_products))
        .route("/v1/product_lines/{id}/products", post(post_product))
        .route("/v1/product_lines/{id}/products/{id}", put(put_product))
}

/*
OTEL: https://rust-api.dev/docs/part-1/observability/

utoipa = { version = "4.2.0", features = ["axum_extras", "chrono"] }
utoipa-swagger-ui = { version = "6", features = ["axum"] }

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::hello::hello,
    ),
    components(
        schemas(

        ),
    ),
    tags(
        (name = "hello", description = "Hello"),
    ),
    servers(
        (url = "/v1", description = "Local server"),
    ),
)]
*/
pub async fn get_products(
    State(state): State<AppState>,
    Path(pl_id): Path<i16>,
) -> Result<Json<Vec<EnProduct>>, ErrorMsg> {
    let result: Vec<EnProduct> =
        facade::select_product_by_product_line_id(&state.pool, &pl_id).await?;
    Ok(Json(result))
}

/**
 * TODO verify the product belongs to the product line.
 */
pub async fn put_product(
    State(state): State<AppState>,
    Path((pl_id, p_id)): Path<(i16, i16)>,
    Query(lang): Query<WsUserLang>,
    claims: UserClaims,
    JsonExtract(title): JsonExtract<EnTitle>,
) -> Result<(), ErrorMsg> {
    if !claims.security {
        return Err(crate::error::unauthorized_error(&lang));
    }

    let mut tx: Transaction<'static, Postgres> = state.pool.begin().await?;
    facade::update_product(&mut tx, &title, p_id).await?;
    tx.commit().await?;

    Ok(())
}

pub async fn post_product(
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

/**
 * TODO verify the product belongs to the product line.
 */
pub async fn delete_product(
    State(state): State<AppState>,
    Path((pl_id, p_id)): Path<(i16, i16)>,
    claims: UserClaims,
    Query(lang): Query<WsUserLang>,
) -> Result<(), ErrorMsg> {
    if !claims.security {
        return Err(crate::error::unauthorized_error(&lang));
    }

    let mut tx: Transaction<'static, Postgres> = state.pool.begin().await?;
    crate::facade::delete_by_id(&mut tx, "product", p_id).await?;
    tx.commit().await?;

    Ok(())
}
