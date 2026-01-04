use crate::{
    error::ErrorMsg,
    facade::vulnerable_package_history_facade,
    model::{
        CdxBom, EnPackage, EnProductLine, EnProductLineProducts, EnTitle,
        EnVulnerablePackageHistory, FromQueryProductLineProduct, Vulnerability, map_product_line,
    },
};
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction, postgres::PgPool};

pub async fn insert_vulnerable_package_history(
    tx: &mut Transaction<'static, Postgres>,
    vulnerable_package_history: &EnVulnerablePackageHistory,
) -> Result<i32, sqlx::Error> {
    let row: (i32,) = sqlx::query_as(
        "INSERT INTO vulnerable_package_history(critical,high,medium,low,info,unknown,none,created_date,package_version_id) VALUES ($1,$2,$3,$4,$5,$6,$7) returning id",
    )
    .bind(&vulnerable_package_history.critical)
    .bind(&vulnerable_package_history.high)
    .bind(&vulnerable_package_history.medium)
    .bind(&vulnerable_package_history.low)
    .bind(&vulnerable_package_history.unknown)
    .bind(&vulnerable_package_history.created_date)
    .bind(&vulnerable_package_history.package_version_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(row.0)
}

pub async fn select_vulnerable_package_history_by_package_version_id(
    tx: &mut Transaction<'static, Postgres>,
    package_version_id: &i64,
) -> Result<Vec<EnVulnerablePackageHistory>, ErrorMsg> {
    let items: Vec<EnVulnerablePackageHistory> = sqlx::query_as::<_, EnVulnerablePackageHistory>(
        "SELECT id,critical,high,medium,low,info,unknown,none,created_date,package_version_id FROM vulnerable_package_history
         where package_version_id=$1",
    )
    .bind(package_version_id)
    .fetch_all(&mut **tx)
    .await?;
    Ok(items)
}

pub async fn select_latest_vulnerable_package_history_by_package_version_id(
    tx: &mut Transaction<'static, Postgres>,
    package_version_id: &i64,
) -> Result<EnVulnerablePackageHistory, ErrorMsg> {
    let item: EnVulnerablePackageHistory = sqlx::query_as::<_, EnVulnerablePackageHistory>(
        "SELECT id,critical,high,medium,low,info,unknown,none,created_date,package_version_id FROM vulnerable_package_history
         where package_version_id=$1 ORDER BY created_date DESC LIMIT 1",
    )
    .bind(package_version_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(item)
}
