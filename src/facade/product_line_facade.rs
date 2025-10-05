use crate::{
    error::ErrorMsg,
    model::{
        EnProductLine, EnProductLineProducts, EnTitle, FromQueryProductLineProduct,
        map_product_line,
    },
};
use sqlx::{Postgres, Transaction, postgres::PgPool};

pub async fn insert_product_line(
    tx: &mut Transaction<'static, Postgres>,
    product_line: &EnTitle,
) -> Result<i16, sqlx::Error> {
    let title = ammonia::clean(&product_line.title);

    let row: (i16,) = sqlx::query_as("INSERT INTO product_line(title) VALUES ($1) returning id")
        .bind(&title)
        .fetch_one(&mut **tx)
        .await?;
    Ok(row.0)
}

pub async fn update_product_line(
    tx: &mut Transaction<'static, Postgres>,
    product_line: &EnTitle,
    id: i16,
) -> Result<(), sqlx::Error> {
    let title = ammonia::clean(&product_line.title);

    sqlx::query("update product_line set title=$1 where id=$2")
        .bind(&title)
        .bind(&id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn select_product_lines(
    pool: &PgPool,
) -> Result<Vec<EnProductLineProducts>, sqlx::Error> {
    let items: Vec<FromQueryProductLineProduct> = sqlx::query_as::<_, FromQueryProductLineProduct>(
        "SELECT pl.id as pl_id, pl.title as pl_title,
        p.id as p_id, p.title as p_title, p.product_line_id as p_product_line_id
        FROM product_line pl left join product p on pl.id = p.product_line_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(map_product_line(items))
}


pub async fn select_product_line_by_id(
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
