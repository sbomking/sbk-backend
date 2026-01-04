use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Serialize, Deserialize, FromRow)]
pub struct EnPackage {
    pub id: i32,
    pub title: String,
    pub description: Option<String>,
    pub product_id: i32,
}

#[derive(Serialize, Deserialize, FromRow)]
pub struct EnPackageVersion {
    pub id: i64,
    pub title: String,
    pub latest_scan: Option<chrono::DateTime<chrono::Utc>>,
    pub package_id: i32,
    pub sbom_id: Option<i64>,
}

#[derive(Serialize, Deserialize, FromRow)]
pub struct EnPackageVersionDeploymentEnvironment {
    pub package_version_id: i64,
    pub deployment_environment_id: i16,
}
