use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Serialize, Deserialize, FromRow)]
pub struct EnDeploymentEnvironment {
    pub id: Option<i16>,
    pub title: String,
    pub internal: bool,
}

#[derive(Serialize, Deserialize, FromRow)]
pub struct EnPackageVersionDeploymentEnvironment {
    pub package_version_id: i64,
    pub deployment_environment_id: i16,
}
