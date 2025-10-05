use sqlx::{Postgres, Transaction};


pub async fn delete_by_id<T>(
    tx: &mut Transaction<'static, Postgres>,
    table_name: &str,
    id: T,
) -> Result<(), sqlx::Error>
where
    T: for<'q> sqlx::Encode<'q, Postgres> + sqlx::Type<Postgres> + Send + Sync,
{
    // Note: format! is used here. Make sure that table_name is a trusted string,
    // since SQL parameter binding does not cover table names.
    let query = format!("DELETE FROM {} WHERE id=$1", table_name);
    sqlx::query(&query)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

