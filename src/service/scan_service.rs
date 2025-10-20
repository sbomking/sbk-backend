 use crate::{
    client::scan_cdx, error::ErrorMsg, facade::{self, select_product_line_by_id}, model::{AppState, CdxBom, EnProduct, EnProductLine, EnTitle, UserClaims, WsUserLang}
};
use axum::extract::{Multipart, State};
use axum::{
    Router,
    extract::{Json as JsonExtract, Path, Query},
    response::Json,
    routing::{delete, get, post, put},
};
use sqlx::{Postgres, Transaction};

pub fn scan_router() -> Router<AppState> {
    Router::new()
        .route("/v1/scan", post(get_scan))
        .route("/v1/scan/product", get(get_scan_product))
}

/**
 * 
 */
pub async fn get_scan(
    State(state): State<AppState>,
    Query(lang): Query<WsUserLang>,
    mut multipart: Multipart
) -> Result<Json<Vec<EnProduct>>, ErrorMsg> {

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
        
        /**
         * TODO verify if the sbom is a cdx, spdx,...
         */

        let cyclone_dx: CdxBom = serde_json::from_slice(&data).unwrap();
        println!("cyclone_dx {:?}", cyclone_dx.spec_version);

        scan_cdx(&cyclone_dx, &lang.lang).await?;
        /* 
        match cyclone_dx.components {
            Some(components) => {
                for component in components {
                    match component.group {
                        Some(group) => {
                            println!("group {:?}", group);
                            println!("name {:?}", component.name);
                            match component.version {
                                Some(version) => {
                                    println!("version {:?}", version);
                                },
                                None => {}
                            }
                        },
                        None => {}
                    }

                    match component.purl {
                        Some(purl) => {
                            println!("PURL {:?}", purl);
                        },
                        None => {},
                    }

                    match component.cpe {
                        Some(cpe) => {
                            println!("CPE {:?}", cpe);
                        },
                        None => {},
                    }

                    match component.swid {
                        Some(swid) => {
                            println!("swid {:?}", swid);
                        },
                        None => {},
                    }

                    //component.cpe
                    //component.swid

                    match component.hashes {
                        Some(hashes) => {
                            for hash in hashes {
                                println!("hash.content {:?}", hash.content);
                                //HashAlg::MD5 == hash.alg

                                match hash.alg {
                                    crate::model::HashAlg::Md5 => println!("hash.alg: Md5"),
                                    crate::model::HashAlg::Sha1 => println!("hash.alg: Sha1"),
                                    crate::model::HashAlg::Sha256 => println!("hash.alg: Sha256"),
                                    crate::model::HashAlg::Sha384 => println!("hash.alg: Sha384"),
                                    crate::model::HashAlg::Sha512 => println!("hash.alg: Sha512"),
                                    crate::model::HashAlg::Sha3256 => println!("hash.alg: Sha3256"),
                                    crate::model::HashAlg::Sha3384 => println!("hash.alg: Sha3384"),
                                    crate::model::HashAlg::Sha3512 => println!("hash.alg: Sha3512"),
                                    crate::model::HashAlg::Blake2B256 => println!("hash.alg: Blake2B256"),
                                    crate::model::HashAlg::Blake2B384 => println!("hash.alg: Blake2B384"),
                                    crate::model::HashAlg::Blake2B512 => println!("hash.alg: Blake2B512"),
                                    crate::model::HashAlg::Blake3 => println!("hash.alg: Blake3"),
                                };

                            }
                        },
                        None => {},
                    }
                    

                }
            },
            None => {}
        }
        */

        
        



        //println!("RAW JSON DATA {:?}", data);  
    }
    
    let result: Vec<EnProduct> =
        facade::select_product_by_product_line_id(&state.pool, &1).await?;
    Ok(Json(result))
}

/**
 * scan with product_id/alias - version (we fetch the sbom previously stored in db) /v1/scan/product
 * 
 * option to return the previous scan result or to retrigger a scan
 */
pub async fn get_scan_product(
    State(state): State<AppState>,
    Path(pl_id): Path<i16>,
) -> Result<Json<Vec<EnProduct>>, ErrorMsg> {
    let result: Vec<EnProduct> =
        facade::select_product_by_product_line_id(&state.pool, &pl_id).await?;
    Ok(Json(result))
}

