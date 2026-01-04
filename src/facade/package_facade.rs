use crate::{
    error::ErrorMsg,
    model::{
        EnPackage, EnProductLine, EnProductLineProducts, EnTitle, FromQueryProductLineProduct,
        map_product_line,
    },
};
use sqlx::{Postgres, Transaction, postgres::PgPool};

pub async fn insert_package(
    tx: &mut Transaction<'static, Postgres>,
    package: &EnPackage,
) -> Result<i32, sqlx::Error> {
    let title = ammonia::clean(&package.title);

    let row: (i32,) = sqlx::query_as(
        "INSERT INTO package(title, description, product_id) VALUES ($1) returning id",
    )
    .bind(&title)
    .bind(&package.description)
    .bind(&package.product_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(row.0)
}

pub async fn update_package(
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

pub async fn select_package(pool: &PgPool) -> Result<Vec<EnProductLineProducts>, sqlx::Error> {
    let items: Vec<FromQueryProductLineProduct> = sqlx::query_as::<_, FromQueryProductLineProduct>(
        "SELECT pl.id as pl_id, pl.title as pl_title,
        p.id as p_id, p.title as p_title, p.product_line_id as p_product_line_id
        FROM product_line pl left join product p on pl.id = p.product_line_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(map_product_line(items))
}

pub async fn select_package_by_id(
    tx: &mut Transaction<'static, Postgres>,
    id: &i16,
) -> Result<EnProductLine, ErrorMsg> {
    let item: EnProductLine =
        sqlx::query_as::<_, EnProductLine>("SELECT id, title FROM product_line where id=$1")
            .bind(id)
            .fetch_one(&mut **tx)
            .await?;
    Ok(item)
}

pub async fn select_package_by_title_product_id(
    tx: &mut Transaction<'static, Postgres>,
    title: &String,
    product_id: &i32,
) -> Result<EnPackage, ErrorMsg> {
    let item: EnPackage = sqlx::query_as::<_, EnPackage>(
        "SELECT id, title, description, product_id FROM product where title=$1 and product_id=$2",
    )
    .bind(title)
    .bind(product_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(item)
}
