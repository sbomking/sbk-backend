use crate::{
    error::ErrorMsg,
    model::{
        EnPackage, EnProductLine, EnProductLineProducts, EnSbom, EnTitle,
        FromQueryProductLineProduct, map_product_line,
    },
};
use sqlx::{Postgres, Transaction, postgres::PgPool};

pub async fn insert_sbom(
    tx: &mut Transaction<'static, Postgres>,
    sbom: &EnSbom,
) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "INSERT INTO sbom(sbom_enriched,sbom_original,s3_uuid_enriched,s3_uuid_original,sha256) VALUES ($1,$2,$3,$4,$5) returning id",
    )
    .bind(&sbom.sbom_enriched)
    .bind(&sbom.sbom_original)
    .bind(&sbom.s3_uuid_enriched)
    .bind(&sbom.s3_uuid_original)
    .bind(&sbom.sha256)
    .fetch_one(&mut **tx)
    .await?;
    Ok(row.0)
}

pub async fn update_sbom(
    tx: &mut Transaction<'static, Postgres>,
    product_line: &EnTitle,
    id: i16,
) -> Result<(), sqlx::Error> {
    let title = ammonia::clean(&product_line.title);

    sqlx::query("update product_line set title=$1 where id=$2")
        .bind(&title)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn select_sbom_by_id(
    tx: &mut Transaction<'static, Postgres>,
    id: &i64,
) -> Result<Option<EnSbom>, sqlx::Error> {
    let item: Option<EnSbom> = sqlx::query_as::<_, EnSbom>(
        "SELECT s.id, s.sbom_enriched, s.sbom_original, s.s3_uuid_enriched, s.s3_uuid_original, s.sha256
        FROM sbom sb where s.id=$1",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(item)
}

pub async fn select_sbom_by_sha(
    tx: &mut Transaction<'static, Postgres>,
    sha256: &String,
) -> Result<EnSbom, ErrorMsg> {
    let item: EnSbom =
        sqlx::query_as::<_, EnSbom>("SELECT id,sbom_enriched,sbom_original,s3_uuid_enriched,s3_uuid_original,sha256 FROM sbom where sha256=$1")
            .bind(sha256)
            .fetch_one(&mut **tx)
            .await?;
    Ok(item)
}
