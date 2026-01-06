use crate::{
    error::ErrorMsg,
    model::{
        EnPackage, EnPackageVersion, EnProductLine, EnProductLineProducts, EnTitle,
        FromQueryProductLineProduct, map_product_line,
    },
};
use sqlx::{Postgres, Transaction, postgres::PgPool};

pub async fn insert_package_version(
    tx: &mut Transaction<'static, Postgres>,
    package_version: &EnPackageVersion,
) -> Result<i64, sqlx::Error> {
    let title = ammonia::clean(&package_version.title);

    let row: (i64,) = sqlx::query_as(
        "INSERT INTO package_version(title,latest_scan,package_id,sbom_id) VALUES ($1,$2,$3,$4) returning id",
    )
    .bind(&title)
    .bind(&package_version.latest_scan)
    .bind(&package_version.package_id)
    .bind(&package_version.sbom_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(row.0)
}

pub async fn select_package_version_by_title_package_id(
    tx: &mut Transaction<'static, Postgres>,
    title: &String,
    package_id: &i32,
) -> Result<EnPackageVersion, ErrorMsg> {
    let item: EnPackageVersion = sqlx::query_as::<_, EnPackageVersion>(
        "SELECT id,title,latest_scan,package_id,sbom_id FROM package_version where title=$1 and package_id=$2",
    )
    .bind(title)
    .bind(package_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(item)
}
