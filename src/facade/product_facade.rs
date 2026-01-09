use crate::{
    error::ErrorMsg,
    model::{EnProduct, EnTitle, FromQueryReProduct, ReProduct, map_reproduct},
};
use sqlx::{Postgres, Transaction, postgres::PgPool};

pub async fn insert_product(
    tx: &mut Transaction<'static, Postgres>,
    product: &EnProduct,
) -> Result<i32, sqlx::Error> {
    let title = ammonia::clean(&product.title);

    let row: (i32,) =
        sqlx::query_as("INSERT INTO product(title,product_line_id) VALUES ($1,$2) returning id")
            .bind(&title)
            .bind(product.product_line_id)
            .fetch_one(&mut **tx)
            .await?;
    Ok(row.0)
}

pub async fn update_product(
    tx: &mut Transaction<'static, Postgres>,
    title: &EnTitle,
    id: i16,
) -> Result<(), sqlx::Error> {
    let title = ammonia::clean(&title.title);

    sqlx::query("update product set title=$1 where id=$2")
        .bind(&title)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn select_product_by_product_line_id(
    pool: &PgPool,
    product_line_id: &i16,
) -> Result<Vec<EnProduct>, ErrorMsg> {
    let items: Vec<EnProduct> = sqlx::query_as::<_, EnProduct>(
        "SELECT id, title, product_line_id FROM product where product_line_id=$1",
    )
    .bind(product_line_id)
    .fetch_all(pool)
    .await?;
    Ok(items)
}

/**TODO return option */
pub async fn select_product_by_title_product_line_id(
    tx: &mut Transaction<'static, Postgres>,
    title: &String,
    product_line_id: &i16,
) -> Result<EnProduct, ErrorMsg> {
    let item: EnProduct = sqlx::query_as::<_, EnProduct>(
        "SELECT id, title, product_line_id FROM product where title=$1 and product_line_id=$2",
    )
    .bind(title)
    .bind(product_line_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(item)
}

pub async fn select_reproduct_by_id(
    tx: &mut Transaction<'static, Postgres>,
    product_id: &i32,
) -> Result<Option<ReProduct>, ErrorMsg> {
    let items: Vec<FromQueryReProduct> = sqlx::query_as::<_, FromQueryReProduct>(
        "SELECT p.id as p_id, p.title as p_title, p.product_line_id as p_product_line_id,
            pkg.id as pkg_id, pkg.title as pkg_title, pkg.description as pkg_description, pkg.product_id as pkg_product_id,
            pkgv.id as pkgv_id, pkgv.title as pkgv_title, pkgv.latest_scan as pkgv_latest_scan, pkgv.sbom_id as pkgv_sbom_id, pkgv.package_id as pkgv_package_id,
            de.id as de_id, de.internal as de_internal, de.title as de_title,
            vph.id as vph_id, vph.critical as vph_critical, vph.high as vph_high, vph.medium as vpb_medium, vph.low as vph_low, vph.info as vph_info, vph._unknown as vph_unknown,
            vph._none as vph_none, vph.created_date as vph_created_date, vph.package_version_id as vph_package_version_id
            FROM product p
            INNER JOIN package pkg on p.id = pkg.product_id
            LEFT JOIN package_version pkgv on pkg.id = pkgv.package_id
            left join package_version_deployment_environment pvde on pkgv.id = pvde.package_version_id
            left join deployment_environment de on de.id = pvde.deployment_environment_id
            left join vulnerable_package_history vph on vph.package_version_id = pkgv.id
            WHERE p.id=$1",
    )
    .bind(product_id)
    .fetch_all(&mut **tx)
    .await?;
    Ok(map_reproduct(items))
}
