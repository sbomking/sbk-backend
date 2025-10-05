use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::request;
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use http_body_util::BodyExt;
use hyper::StatusCode;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use tower::{Service, ServiceExt};

use crate::{
    auth::OauthKeySmall,
    client::{get_hyper_client, get_hyper_client_unsecure},
    error::ErrorMsg,
    model::{AUD, AUTHORITY_URL, ClaimsZit, ISS, UserClaims, ZitOauthKeys, kid_ne_rwlock},
};

/**Used in all webservice request. Aims to provide the token information (roles,...).
 * This part should be improved in term of error handling.
 */
//#[async_trait]
//#[trait]
impl<S> FromRequestParts<S> for UserClaims
where
    S: Send + Sync,
{
    type Rejection = ErrorMsg;

    /**
     * Get the Oauth token, validate it (iss, aud & signature) and decode it.
     * Return a small UserClaims struct.
     */
    async fn from_request_parts(
        req: &mut request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let status = 123;
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(req, &status)
                .await
                .map_err(|_| ErrorMsg {
                    title: "InvalidToken".parse().unwrap(),
                    status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    _type: None,
                    detail: None,
                    instance: None,
                    code: None,
                    errors: vec![],
                })?;
        /*
        tracing::error!("bearer.token {:?}", bearer.token());
        println!("bearer.token {:?}", bearer.token());
        */

        let header = decode_header(bearer.token())?;
        let kid = match header.kid {
            Some(k) => k,
            None => "NO KID".to_string(), /*return Err("Token doesn't have a `kid` header field".into())*/
        };

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[AUD.to_string()]);
        validation.set_issuer(&[ISS.to_string()]);
        /*
        tracing::error!("kid {:?}", kid);
        println!("kid {:?}", kid);
         */

        let mut n = String::from("");
        let mut e = String::from("");

        {
            match kid_ne_rwlock().read() {
                Ok(kne_ref) => {
                    for oauth_key in kne_ref.iter() {
                        if oauth_key.kid == kid {
                            e = oauth_key.e.to_string();
                            n = oauth_key.n.to_string();
                            break;
                        }
                    }
                }
                Err(err) => {
                    tracing::error!("Kid rwLock Read error {}", err);
                    println!("Kid rwLock Read error {}", err);
                }
            };
        }

        let token2_res = decode::<ClaimsZit>(
            bearer.token(),
            &DecodingKey::from_rsa_components(n.as_str(), e.as_str())?,
            &validation,
        );

        /*
         * If the token is invalid, it could be that our oauth key might not be valid anymore and we need to renew it.
         * It also serve a lazy loading as we do not fetch the oauth key at startup of the application.
         */
        let token2 = match token2_res {
            Ok(token_data) => token_data,
            Err(error) => {
                tracing::error!("{:?}", error);
                update_oidc_key().await?;
                {
                    match kid_ne_rwlock().read() {
                        Ok(kne_ref) => {
                            for oauth_key in kne_ref.iter() {
                                if oauth_key.kid == kid {
                                    e = oauth_key.e.to_string();
                                    n = oauth_key.n.to_string();
                                    break;
                                }
                            }
                        }
                        Err(err) => {
                            tracing::error!("Kid rwLock Read error {}", err);
                            println!("Kid rwLock Read error {}", err);
                        }
                    };
                }
                tracing::error!("Update OIDC key done");
                decode::<ClaimsZit>(
                    bearer.token(),
                    &DecodingKey::from_rsa_components(n.as_str(), e.as_str())?,
                    &validation, /*&Validation::new(Algorithm::RS256)*/
                )?
            }
        };

        //tracing::error!("{:?}", token2.claims.preferred_username);
        //println!("{:?}", token2.claims.preferred_username);

        let claims_tournament: UserClaims = match token2.claims.roles {
            Some(roles) => UserClaims {
                sub: token2.claims.sub,
                security: roles.contains_key("security"),
            },
            None => UserClaims {
                sub: token2.claims.sub,
                security: false,
            },
        };

        Ok(claims_tournament)
    }
}

/**
 * Call the OIDC server to update the public JWT.
 */
pub async fn update_oidc_key() -> Result<bool, ErrorMsg> {
    let done = false;
    tracing::info!("update_oidc_key");
    println!("update_oidc_key");

    let prod = crate::model::PROD.as_str();
    let uri = AUTHORITY_URL.as_str();
    let request = hyper::Request::builder()
        .method("GET")
        .uri(uri)
        .header("Content-Type", "application/json")
        .version(hyper::Version::HTTP_2)
        .body(Body::empty())?;

    let response = if String::from("true").eq(&prod) {
        tracing::info!("Before calling get_hyper_client");
        get_hyper_client()?.ready().await?.call(request).await?
    } else {
        tracing::info!("Before calling get_hyper_client_unsecure");
        get_hyper_client_unsecure()
            .await?
            .ready()
            .await?
            .call(request)
            .await?
    };

    let keys_str: String = if response.status() != StatusCode::OK {
        println!("update_oidc_key response: {} ", response.status());
        //let body_bytes = axum::body::to_bytes(response.into_body(), MAX_BODY_SIZE).await?;
        let body_bytes = response.into_body().collect().await?.to_bytes();
        let str = String::from_utf8(body_bytes.to_vec())?;
        tracing::info!("update_oidc_key response body {} ", str);
        println!("update_oidc_key response body {} ", str);
        return Err(ErrorMsg {
            title: "Impossible to fetch token".to_string(),
            status: StatusCode::UNAUTHORIZED.as_u16(),
            _type: None,
            detail: None,
            instance: None,
            code: None,
            errors: vec![],
        });
    } else {
        tracing::info!("else update_oidc_key response {} ", response.status());
        println!("else update_oidc_key response: {} ", response.status());
        //let body_bytes = axum::body::to_bytes(response.into_body(), MAX_BODY_SIZE).await?;
        let body_bytes = response.into_body().collect().await?.to_bytes();
        let str = String::from_utf8(body_bytes.to_vec())?;
        tracing::info!("else update_oidc_key Body bytes {} ", str);
        //println!("Body bytes {} ", str);
        str
    };

    // Parse the string of data into serde_json::Value.
    let v: ZitOauthKeys = serde_json::from_str(&keys_str)?;
    {
        match kid_ne_rwlock().write() {
            Ok(mut kid_ne) => kid_ne.clear(),
            Err(err) => {
                tracing::error!("RwLock error {}", err);
                println!("RwLock error {}", err);
            }
        };
    }

    for key in v.keys {
        tracing::error!("Token key.n {} ", key.n);
        println!("Token key.n {} ", key.n);

        {
            match kid_ne_rwlock().write() {
                Ok(mut kid_ne) => kid_ne.push(OauthKeySmall {
                    kid: key.kid,
                    e: key.e,
                    n: key.n,
                }),
                Err(err) => {
                    tracing::error!("RwLock error {}", err);
                    println!("RwLock error {}", err);
                }
            };
        }
    }

    Ok(done)
}
