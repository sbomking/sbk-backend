use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::model::{EnDeploymentEnvironment, EnVulnerablePackageHistory};

/**
 * Re for request response. En for entity
 */
#[derive(Serialize, Deserialize, FromRow)]
pub struct ReProduct {
    pub id: i32,
    pub title: String,
    pub product_line_id: i16,
    pub packages: Vec<RePackage>,
}

#[derive(Serialize, Deserialize, FromRow)]
pub struct RePackage {
    pub id: i32,
    pub title: String,
    pub description: Option<String>,
    pub product_id: i32,
    pub versions: Vec<RePackageVersion>,
}

#[derive(Serialize, Deserialize, FromRow)]
pub struct RePackageVersion {
    pub id: i64,
    pub title: String,
    pub latest_scan: Option<chrono::DateTime<chrono::Utc>>,
    pub package_id: i32,
    pub sbom_id: Option<i64>,
    pub deployment: EnDeploymentEnvironment,
    pub latest_vulnerable_package_history: Option<EnVulnerablePackageHistory>,
}

#[derive(Serialize, Deserialize, FromRow)]
pub struct FromQueryReProduct {
    pub p_id: i32,
    pub p_title: String,

    pub pkg_id: Option<i32>,
    pub pkg_title: String,
    pub pkg_description: Option<String>,
    pub pkg_product_id: Option<i16>,

    pub pkgv_id: Option<i32>,
    pub pkgv_title: Option<String>,
    pub pkgv_latest_scan: Option<chrono::DateTime<chrono::Utc>>,
    pub pkgv_sbom_id: Option<i64>,
    pub pkgv_package_id: Option<i32>,

    pub de_id: Option<i64>,
    pub de_internal: Option<bool>,
    pub de_title: Option<String>,

    pub vph_id: Option<i64>,
    pub vph_critical: Option<i16>,
    pub vph_high: Option<i16>,
    pub vpb_medium: Option<i16>,
    pub vph_low: Option<i16>,
    pub vph_info: Option<i16>,
    pub vph_unknown: Option<i16>,
    pub vph_none: Option<i16>,
    pub vph_created_date: Option<chrono::DateTime<chrono::Utc>>,
    pub vph_package_version_id: Option<i64>,
}

pub fn map_reproduct(items: Vec<FromQueryReProduct>) -> Vec<ReProduct> {
    let mut products: Vec<ReProduct> = vec![];

    for res in items {
        /*
        match product_lines.iter_mut().find(|pl| pl.id == res.pl_id) {
            Some(_product_line) => {}
            None => {
                let product_line: EnProductLineProducts = EnProductLineProducts {
                    id: res.pl_id,
                    title: res.pl_title,
                    //owners: res.pl_owners,
                    products: vec![],
                };
                product_lines.push(product_line);
            }
        };

        if let Some(p_id) = res.p_id {
            if let Some(p_title) = res.p_title {
                if let Some(p_product_line_id) = res.p_product_line_id {
                    if let Some(product_line) =
                        product_lines.iter_mut().find(|pl| pl.id == res.pl_id)
                    {
                        product_line.products.push(EnProduct {
                            id: p_id,
                            title: p_title,
                            product_line_id: p_product_line_id,
                        });
                    };
                };
            };
        };
         */
    }

    products.sort_by(|a, b| a.title.cmp(&b.title));
    products
}
