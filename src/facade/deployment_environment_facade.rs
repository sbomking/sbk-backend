use crate::{
    error::ErrorMsg,
    model::{
        EnDeploymentEnvironment, EnPackageVersionDeploymentEnvironment, EnProductLine,
        EnProductLineProducts, EnTitle, FromQueryProductLineProduct, map_product_line,
    },
};
use sqlx::{Postgres, Transaction, postgres::PgPool};

pub async fn insert_deployment_environment(
    tx: &mut Transaction<'static, Postgres>,
    deployment_environment: &EnDeploymentEnvironment,
) -> Result<i16, sqlx::Error> {
    let title = ammonia::clean(&deployment_environment.title);

    let row: (i16,) = sqlx::query_as(
        "INSERT INTO deployment_environment(title,internal) VALUES ($1,$2) returning id",
    )
    .bind(&title)
    .bind(&deployment_environment.internal)
    .fetch_one(&mut **tx)
    .await?;
    Ok(row.0)
}

pub async fn insert_package_version_deployment_environment(
    tx: &mut Transaction<'static, Postgres>,
    package_version_deployment_environment: &EnPackageVersionDeploymentEnvironment,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO sca.package_version_deployment_environment(package_version_id, deployment_environment_id) VALUES ($1, $2)",
    )
    .bind(package_version_deployment_environment.package_version_id)
    .bind(package_version_deployment_environment.deployment_environment_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn update_deployment_environment(
    tx: &mut Transaction<'static, Postgres>,
    deployment_environment: &EnDeploymentEnvironment,
) -> Result<(), sqlx::Error> {
    let title = ammonia::clean(&deployment_environment.title);

    sqlx::query("update product_line set title=$1 internal=$2 where id=$3")
        .bind(&title)
        .bind(&deployment_environment.internal)
        .bind(deployment_environment.id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn select_deployment_environment(
    pool: &PgPool,
) -> Result<Vec<EnDeploymentEnvironment>, sqlx::Error> {
    let items: Vec<EnDeploymentEnvironment> = sqlx::query_as::<_, EnDeploymentEnvironment>(
        "SELECT de.id, de.title, de.internal FROM update_deployment_environment de",
    )
    .fetch_all(pool)
    .await?;
    Ok(items)
}

pub async fn select_deployment_environment_by_title(
    tx: &mut Transaction<'static, Postgres>,
    deployment_title: &String,
) -> Result<Option<EnDeploymentEnvironment>, sqlx::Error> {
    let title = ammonia::clean(&deployment_title);

    let item: Option<EnDeploymentEnvironment> = sqlx::query_as::<_, EnDeploymentEnvironment>(
        "SELECT de.id, de.title, de.internal FROM deployment_environment de where de.title=$1",
    )
    .bind(title)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(item)
}
