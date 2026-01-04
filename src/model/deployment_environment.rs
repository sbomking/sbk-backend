use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Serialize, Deserialize, FromRow)]
pub struct EnDeploymentEnvironment {
    pub id: Option<i16>,
    pub title: String,
    pub internal: bool,
}
