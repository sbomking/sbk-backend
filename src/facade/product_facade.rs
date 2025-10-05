use crate::{
    error::ErrorMsg,
    model::{EnProduct, EnTitle},
};
use sqlx::{Postgres, Transaction, postgres::PgPool};

pub async fn insert_product(
    tx: &mut Transaction<'static, Postgres>,
    product: &EnTitle,
) -> Result<i16, sqlx::Error> {
    let title = ammonia::clean(&product.title);

    let row: (i16,) = sqlx::query_as("INSERT INTO product(title) VALUES ($1) returning id")
        .bind(&title)
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
        .bind(&id)
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
