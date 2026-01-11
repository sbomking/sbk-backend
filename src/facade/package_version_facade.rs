use crate::{
    error::ErrorMsg,
    model::{
        EnPackage, EnPackageVersion, EnProductLine, EnProductLineProducts, EnTitle,
        FromQueryProductLineProduct, FromQueryRePackage, RePackage, map_product_line,
        map_repackage,
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

pub async fn select_package_version_by_id(
    tx: &mut Transaction<'static, Postgres>,
    package_version_id: &i64,
) -> Result<Option<RePackage>, ErrorMsg> {
    let items: Vec<FromQueryRePackage> = sqlx::query_as::<_, FromQueryRePackage>(
        "SELECT pkg.id as pkg_id, pkg.title as pkg_title, pkg.description as pkg_description, pkg.product_id as pkg_product_id,
            pkgv.id as pkgv_id, pkgv.title as pkgv_title, pkgv.latest_scan as pkgv_latest_scan, pkgv.sbom_id as pkgv_sbom_id, pkgv.package_id as pkgv_package_id,
            de.id as de_id, de.internal as de_internal, de.title as de_title,
            vph.id as vph_id, vph.critical as vph_critical, vph.high as vph_high, vph.medium as vpb_medium, vph.low as vph_low, vph.info as vph_info, vph._unknown as vph_unknown,
            vph._none as vph_none, vph.created_date as vph_created_date, vph.package_version_id as vph_package_version_id
            FROM package pkg
            LEFT JOIN package_version pkgv on pkg.id = pkgv.package_id
            left join package_version_deployment_environment pvde on pkgv.id = pvde.package_version_id
            left join deployment_environment de on de.id = pvde.deployment_environment_id
            left join vulnerable_package_history vph on vph.package_version_id = pkgv.id
            WHERE pkgv.id=$1",
    )
    .bind(package_version_id)
    .fetch_all(&mut **tx)
    .await?;
    Ok(map_repackage(items))
}
