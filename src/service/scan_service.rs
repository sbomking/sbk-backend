use crate::{
    client::scan_cdx,
    error::ErrorMsg,
    facade::{self, select_product_line_by_id},
    model::{AppState, CdxBom, EnProduct, EnProductLine, EnTitle, UserClaims, WsUserLang},
};
use axum::extract::{Multipart, State};
use axum::{
    Router,
    extract::{Json as JsonExtract, Path, Query},
    response::Json,
    routing::{delete, get, post, put},
};
use sqlx::{Postgres, Transaction};

//TODO put api in front of all api. So api/v1/... Easier for reverse proxy.
//TODO rename the route to /v1/product/id/scan or /v1/product_line/id/product/id/scan
//TODO generate SARIF
pub fn scan_router() -> Router<AppState> {
    Router::new().route("/api/v1/scan", post(get_scan))
    //.route("/v1/scan/product", get(get_scan_product))
}

/**
 * TODO DECIDE what to return as value.
 * Only a simple scan used for pr scanning.
 * It does not update the package. See /v1/bom to update product and package version.
 */
pub async fn get_scan(
    State(state): State<AppState>,
    Query(lang): Query<WsUserLang>,
    mut multipart: Multipart,
) -> Result<Json<Vec<crate::model::Vulnerability>>, ErrorMsg> {
    let mut vulnerabilities: Vec<crate::model::Vulnerability> = vec![];

    while let Some(field) = multipart.next_field().await.unwrap() {
        let data = field.bytes().await.unwrap();
        /*
        let name = field.name().unwrap().to_string();
        let file_name = field.file_name().unwrap().to_string();
        let content_type = field.content_type().unwrap().to_string();


        println!(
            "Length of `{name}` (`{file_name}`: `{content_type}`) is {} bytes",
            data.len()
        );
        */

        /*
         * TODO verify if the sbom is a cdx, spdx,...
         */
        let cyclone_dx: CdxBom = serde_json::from_slice(&data).unwrap();
        println!("cyclone_dx {:?}", cyclone_dx.spec_version);

        vulnerabilities = scan_cdx(&cyclone_dx, &lang.lang).await?;
        //println!("RAW JSON DATA {:?}", data);
    }

    Ok(Json(vulnerabilities))
}

/*
 * scan with product_id/alias - version (we fetch the sbom previously stored in db) /v1/scan/product
 *
 * option to return the previous scan result or to retrigger a scan
 */
/*
pub async fn get_scan_product(
    State(state): State<AppState>,
    Path(pl_id): Path<i16>,
) -> Result<Json<Vec<EnProduct>>, ErrorMsg> {
    let result: Vec<EnProduct> =
        facade::select_product_by_product_line_id(&state.pool, &pl_id).await?;
    Ok(Json(result))
}
 */
