use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

//SpdxSchemaJson => String
//pub struct Schema => pub struct CdxBom
/**
 * https://cyberphone.github.io/doc/security/jsf.html
 */
#[derive(Serialize, Deserialize, FromRow, Clone, PartialEq, Debug)]
pub struct JsfSignature {
    algorithm: String,
    keyId: Option<String>,
    publicKey: Option<String>,
    certificatePath: Option<String>,
    value: String,
}

#[derive(Serialize, Deserialize, FromRow, Clone, PartialEq, Debug)]
pub struct JsfPublicKey {
    kty: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    n: Option<String>,
    e: Option<String>,
}