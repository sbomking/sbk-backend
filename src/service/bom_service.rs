use crate::{
    error::ErrorMsg,
    facade::{self, insert_product_line, select_product_line_by_id},
    model::{
        AppState, CdxBom, EnPackage, EnPackageVersion, EnProduct, EnProductLine, EnSbom, EnTitle,
        UserClaims, WsUserLang,
    },
    util::{get_message, validate_entity},
};
use axum::extract::{Multipart, State};
use axum::{
    Router,
    extract::{Json as JsonExtract, Query},
    response::Json,
    routing::post,
};
use hyper::StatusCode;
use sha2::Digest;
use sqlx::{Postgres, Transaction};

pub fn bom_router() -> Router<AppState> {
    //Router::new().route("/v1/product_lines/{id}/products/{id}/bom", post(post_bom))
    Router::new().route("/v1/bom", post(post_bom))
}

/**
* TODO think about passing an API KEY or token for CI/CD integration.
* curl -X POST http://localhost:xxxx/v1/bom \
  -H "Content-Type: multipart/form-data" \
  -F "productline=productline" \
  -F "product=product" \
  -F "package=package" \
  -F "version=version" \
  -F "environment=environment" \
  -F "bom=@target/bom.xml"
*/
pub async fn post_bom(
    State(state): State<AppState>,
    Query(lang): Query<WsUserLang>,
    claims: UserClaims,
    mut multipart: Multipart,
) -> Result<Json<Vec<crate::model::Vulnerability>>, ErrorMsg> {
    let mut vulnerabilities: Vec<crate::model::Vulnerability> = vec![];

    let mut product_line_id: i16 = 0;

    let mut product: Option<String> = None;
    let mut package: Option<String> = None;
    let mut package_version: Option<String> = None;

    let mut cdx_bom: Option<CdxBom> = None;
    let mut bom_hex_sha256: String = String::from("");

    let mut tx: Transaction<'static, Postgres> = state.pool.begin().await?;

    /*
     * The field might be stored in different order.
     * The handling should be sequential so we store the product, package, package_versio and sbom
     */
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap_or("").to_string();

        match &field.bytes().await {
            Ok(bytes) => {
                let field_str = String::from_utf8(bytes.to_vec())?;
                //tracing::error!("Body bytes {} ", field_str);
                //println!("Body bytes {} ", field_str);
                match name.as_str() {
                    "productline" => {
                        product_line_id =
                            match facade::select_product_line_by_title(&mut tx, &field_str).await {
                                Ok(product_line) => product_line.id,
                                Err(_) => {
                                    facade::insert_product_line(
                                        &mut tx,
                                        &EnTitle { title: field_str },
                                    )
                                    .await?
                                }
                            };
                    }
                    "product" => {
                        product = Some(field_str);
                    }
                    "package" => {
                        product = Some(field_str);
                    }
                    "version" => {
                        package_version = Some(field_str);
                    }
                    "bom" => {
                        //let cyclone_dx: CdxBom = serde_json::from_slice(&data).unwrap();
                        let sha2 = sha2::Sha256::digest(bytes);
                        bom_hex_sha256 = sha2.iter().map(|b| format!("{:02x}", b)).collect();
                        cdx_bom = Some(serde_json::from_str(&field_str)?)
                    }
                    _ => {
                        let error = String::from(
                            "Supported form data parameters are productline, product, package, version and bom. Unknown: ",
                        ) + &name;
                        return Err(crate::error::simple_error(&error, &StatusCode::CONFLICT));
                    }
                }
            }
            Err(_) => {
                let error = String::from("Invalid multipart field: ") + &name;
                return Err(crate::error::simple_error(&error, &StatusCode::CONFLICT));
            }
        };
    }

    let product_id: i32 = match product {
        Some(product_title) => {
            match facade::select_product_by_title_product_line_id(
                &mut tx,
                &product_title,
                &product_line_id,
            )
            .await
            {
                Ok(product) => product.id,
                Err(_) => {
                    let new_product: EnProduct = EnProduct {
                        id: 0,
                        title: product_title,
                        product_line_id,
                    };
                    facade::insert_product(&mut tx, &new_product).await?
                }
            }
        }
        None => {
            return Err(crate::error::simple_error(
                &String::from("Product must be filled"),
                &StatusCode::CONFLICT,
            ));
        }
    };

    let package_id: i32 = match package {
        Some(package_title) => {
            match facade::select_package_by_title_product_id(&mut tx, &package_title, &product_id)
                .await
            {
                Ok(package) => package.id,
                Err(_) => {
                    let new_package: EnPackage = EnPackage {
                        id: 0,
                        title: package_title,
                        description: None,
                        product_id,
                    };
                    facade::insert_package(&mut tx, &new_package).await?
                }
            }
        }
        None => {
            return Err(crate::error::simple_error(
                &String::from("Package must be filled"),
                &StatusCode::CONFLICT,
            ));
        }
    };

    let sbom_id: i64 = match cdx_bom {
        Some(sbom) => match facade::select_sbom_by_sha(&mut tx, &bom_hex_sha256).await {
            Ok(en_sbom) => {
                return Err(crate::error::simple_error(
                    &String::from("Bom already uploaded"),
                    &StatusCode::CONFLICT,
                ));
            }
            Err(_) => {
                let new_sbom: EnSbom = EnSbom {
                    id: 0,
                    sbom_enriched: None,
                    sbom_original: Some(sqlx::types::Json(serde_json::to_string(&sbom)?)),
                    s3_uuid_original: None,
                    s3_uuid_enriched: None,
                };

                vulnerabilities = crate::client::scan_cdx(&sbom, &lang.lang).await?;
                //TODO enrich the SBOM
                facade::insert_sbom(&mut tx, &new_sbom).await?
            }
        },
        None => {
            return Err(crate::error::simple_error(
                &String::from("Bom must be filled"),
                &StatusCode::CONFLICT,
            ));
        }
    };

    let package_version_id = match package_version {
        Some(package_version_title) => {
            match facade::select_package_version_by_title_package_id(
                &mut tx,
                &package_version_title,
                &product_id,
            )
            .await
            {
                Ok(package_version) => package_version.id,
                Err(_) => {
                    let new_package_version: EnPackageVersion = EnPackageVersion {
                        id: 0,
                        title: package_version_title,
                        latest_scan: None,
                        package_id,
                        sbom_id: Some(sbom_id),
                    };
                    facade::insert_package_version(&mut tx, &new_package_version).await?
                }
            }
        }
        None => {
            return Err(crate::error::simple_error(
                &String::from("Version must be filled"),
                &StatusCode::CONFLICT,
            ));
        }
    };
    /*
    match facade::select_latest_vulnerable_package_history_by_package_version_id(
        &mut tx,
        package_version_id,
    )
    .await
    {
        Ok(vulnerable_package_history) => {

        },
        Err(_) => {

        },
    }
     */

    //select latest package_history...
    //use the function with the vulnerabilties in the function.
    // comapre them.
    // equals, not equals,...
    tx.commit().await?;

    //let result: Vec<EnProduct> = facade::select_product_by_product_line_id(&state.pool, &1).await?;
    //TODO we should only return (uknown: 0, low,: ,....)
    Ok(Json(vulnerabilities))
}

/*
pub async fn post_bom(
    State(state): State<AppState>,
    Query(lang): Query<WsUserLang>,
    claims: UserClaims,
    JsonExtract(product_line): JsonExtract<EnTitle>,
) -> Result<Json<EnProductLine>, ErrorMsg> {
    if !claims.security {
        return Err(crate::error::unauthorized_error(&lang));
    }


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


    let mut tx: Transaction<'static, Postgres> = state.pool.begin().await?;
    let id: i16 = facade::insert_product(&mut tx, &product_line).await?;
    tx.commit().await?;

    let mut tx: Transaction<'static, Postgres> = state.pool.begin().await?;
    Ok(Json(select_product_line_by_id(&mut tx, &id).await?))
}
*/
