use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct OauthSignedTokenBody {
    pub grant_type: String, //client_credentials
    pub scope: String,      //openid profile urn:zitadel:iam:org:project:id:243492890272071689:aud
    pub assertion: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OauthTokenBody {
    //#[serde(alias = "grant_type", rename = "grant_type")]
    pub grant_type: String, //client_credentials
    pub scope: String,      //openid profile urn:zitadel:iam:org:project:id:243492890272071689:aud
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Serialize, Deserialize)]
pub struct OauthTokenResponse {
    pub access_token: String,
    pub token_type: String, //bearer
    pub expires_in: i64,
    pub id_token: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct OauthKeySmall {
    pub n: String,
    pub kid: String,
    pub e: String,
}

/**
 * Claims to encode
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct OauthClaim {
    //service_user_id
    pub iss: String,
    //service_user_id
    pub sub: String,
    //oidc_server_url
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
}
