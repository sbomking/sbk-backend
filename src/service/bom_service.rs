use crate::{
    error::ErrorMsg,
    facade::{self},
    model::{
        AppState, CdxBom, EnDeploymentEnvironment, EnPackage, EnPackageVersion,
        EnPackageVersionDeploymentEnvironment, EnProduct, EnSbom, EnTitle,
        EnVulnerablePackageHistory, UserClaims, WsUserLang,
    },
};
use axum::extract::{Multipart, State};
use axum::{
    Router,
    extract::{Json as JsonExtract, Path, Query},
    response::Json,
    routing::{delete, get, post, put},
};
use chrono::Utc;
use hyper::StatusCode;
use sha2::Digest;
use sqlx::{Postgres, Transaction};

pub fn bom_router() -> Router<AppState> {
    //Router::new().route("/v1/product_lines/{id}/products/{id}/bom", post(post_bom))
    Router::new()
        .route("/api/v1/bom/{id}", get(get_bom))
        .route("/api/v1/bom", post(post_bom))
}

pub async fn get_bom(
    State(state): State<AppState>,
    Path(sbom_id): Path<i64>,
) -> Result<Json<Option<CdxBom>>, ErrorMsg> {
    let mut tx: Transaction<'static, Postgres> = state.pool.begin().await?;
    let result: Option<EnSbom> = facade::select_sbom_by_id(&mut tx, &sbom_id).await?;

    let cdx_bom: Option<CdxBom> = match result {
        Some(bom) => match bom.sbom_enriched {
            Some(sbom_enriched) => {
                serde_json::from_str::<Option<CdxBom>>(&sbom_enriched)?
                //serde_json::from_str(&bom.sbom_enriched)?
            }
            None => None,
        },
        None => None,
    };

    Ok(Json(cdx_bom))
}

/**
 * TODO translated error message.
 * TODO Must be able to send XML data as well.
 * TODO think about passing an API KEY or bearer token for CI/CD integration.
 * curl -X POST http://localhost:5002/v1/bom?lang=en \
   -H "Content-Type: multipart/form-data" \
   -F "productline=productline" \
   -F "product=product" \
   -F "package=package" \
   -F "version=version" \
   -F "environment=environment" \
   -F "bom=@target/bom.json"
*/
pub async fn post_bom(
    State(state): State<AppState>,
    Query(lang): Query<WsUserLang>,
    //claims: UserClaims,
    mut multipart: Multipart,
) -> Result<Json<EnVulnerablePackageHistory>, ErrorMsg> {
    /*if !claims.security {
        return Err(crate::error::unauthorized_error(&lang));
    }
    */

    let mut product_line_id: i16 = 0;

    let mut product: Option<String> = None;
    let mut package: Option<String> = None;
    let mut package_version: Option<String> = None;
    let mut environment: Option<String> = None;

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
                        package = Some(field_str);
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
                    "environment" => environment = Some(field_str),
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

    let mut vulnerable_package_history: EnVulnerablePackageHistory = EnVulnerablePackageHistory {
        id: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        unknown: 0,
        none: 0,
        created_date: Utc::now(),
        package_version_id: 0,
    };

    let sbom_id: i64 = match cdx_bom {
        Some(mut sbom) => match facade::select_sbom_by_sha(&mut tx, &bom_hex_sha256).await {
            Ok(_en_sbom) => {
                return Err(crate::error::simple_error(
                    &String::from("Bom already uploaded"),
                    &StatusCode::CONFLICT,
                ));
            }
            Err(_) => {
                let mut new_sbom: EnSbom = EnSbom {
                    id: 0,
                    sbom_enriched: None,
                    sbom_original: Some(sqlx::types::Json(serde_json::to_string(&sbom)?)),
                    s3_uuid_original: None,
                    s3_uuid_enriched: None,
                    sha256: Some(bom_hex_sha256),
                };

                let vulnerabilities: Vec<crate::model::Vulnerability> =
                    crate::client::scan_cdx(&sbom, &lang.lang).await?;
                vulnerable_package_history.update_vulnerable_package_history(&vulnerabilities);

                sbom.vulnerabilities = Some(vulnerabilities);
                new_sbom.sbom_enriched = Some(sqlx::types::Json(serde_json::to_string(&sbom)?));
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
                &package_id,
            )
            .await
            {
                Ok(package_version) => package_version.id,
                Err(_) => {
                    let new_package_version: EnPackageVersion = EnPackageVersion {
                        id: 0,
                        title: package_version_title,
                        latest_scan: Some(Utc::now()),
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
    vulnerable_package_history.package_version_id = package_version_id;

    let vulnerable_package_history_id: i64 =
        match facade::select_latest_vulnerable_package_history_by_package_version_id(
            &mut tx,
            &package_version_id,
        )
        .await
        {
            Ok(latest_vulnerable_package_history) => {
                if vulnerable_package_history
                    .has_vulnerability_changed(&latest_vulnerable_package_history)
                {
                    facade::insert_vulnerable_package_history(&mut tx, &vulnerable_package_history)
                        .await?
                } else {
                    latest_vulnerable_package_history.id
                }
            }
            Err(_) => {
                facade::insert_vulnerable_package_history(&mut tx, &vulnerable_package_history)
                    .await?
            }
        };
    vulnerable_package_history.id = vulnerable_package_history_id;

    let deployment_environment_id: i16 = match environment {
        Some(env) => match facade::select_deployment_environment_by_title(&mut tx, &env).await? {
            Some(deployment_environment) => deployment_environment.id.unwrap_or(0),
            None => {
                facade::insert_deployment_environment(
                    &mut tx,
                    &EnDeploymentEnvironment {
                        id: None,
                        title: env,
                        internal: false,
                    },
                )
                .await?
            }
        },
        None => {
            return Err(crate::error::simple_error(
                &String::from("Environment must be filled"),
                &StatusCode::CONFLICT,
            ));
        }
    };

    facade::insert_package_version_deployment_environment(
        &mut tx,
        &EnPackageVersionDeploymentEnvironment {
            package_version_id,
            deployment_environment_id,
        },
    )
    .await?;
    tx.commit().await?;

    Ok(Json(vulnerable_package_history))
}
