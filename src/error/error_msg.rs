use crate::model::WsUserLang;
use crate::util::get_message;
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cell::BorrowError;

const ERR: &str = "Error";

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorDetail {
    //granular description on the specific error.
    pub detail: String,
    //Opt, Json point to a specific request body property.
    pub pointer: Option<String>,
    //Opt, The name of the query or path param.
    pub parameter: Option<String>,
    //Opt, header that is the source of the error.
    pub header: Option<String>,
    //Opt, Specific codes to identity the error content.
    pub code: Option<String>,
}

/**
 * Generic error message.
 * Follows the RFC 9457
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorMsg {
    //Opt, URI reference that identifies the problem type.
    #[serde(alias = "type", rename = "type")]
    pub _type: Option<String>,
    //Opt, Human readable explanation specific to this occurence of the problem.
    pub detail: Option<String>,
    //Opt, URI specify the
    pub instance: Option<String>,
    pub code: Option<String>,

    //Opt, http_status code
    pub status: u16,
    //Opt, Summary of the problem type
    pub title: String,

    pub errors: Vec<ErrorDetail>,
}

pub fn unauthorized_error(lang: &WsUserLang) -> ErrorMsg {
    return ErrorMsg {
        title: get_message(&*lang.lang, &"unauthorized", &None),
        status: StatusCode::UNAUTHORIZED.as_u16(),
        _type: None,
        detail: None,
        instance: None,
        code: None,
        errors: vec![],
    };
}

pub fn simple_error(title: &String) -> ErrorMsg {
    return ErrorMsg {
        title: title.to_string(),
        status: StatusCode::CONFLICT.as_u16(),
        _type: None,
        detail: None,
        instance: None,
        code: None,
        errors: vec![],
    };
}

impl From<sqlx::Error> for ErrorMsg {
    fn from(inner: sqlx::Error) -> Self {
        tracing::error!("DB error: {}", inner);
        println!("DB error {:?}", inner);
        ErrorMsg {
            title: ERR.to_string(),
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            _type: None,
            detail: None,
            instance: None,
            code: None,
            errors: vec![],
        }
    }
}

impl From<jsonwebtoken::errors::Error> for ErrorMsg {
    fn from(inner: jsonwebtoken::errors::Error) -> Self {
        tracing::error!("jsonwebtoken error {}", inner);
        println!("jsonwebtoken error {:?}", inner);

        //TODO handle better error message for ExpiredSignature like please reconnect.
        ErrorMsg {
            title: ERR.to_string(),
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            _type: None,
            detail: None,
            instance: None,
            code: None,
            errors: vec![],
        }
    }
}

impl From<axum::http::Error> for ErrorMsg {
    fn from(inner: axum::http::Error) -> Self {
        tracing::error!("axum::http::Error {:?}", inner);
        println!("axum::http::Error {:?}", inner);
        ErrorMsg {
            title: ERR.to_string(),
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            _type: None,
            detail: None,
            instance: None,
            code: None,
            errors: vec![],
        }
    }
}

impl From<hyper_util::client::legacy::Error> for ErrorMsg {
    fn from(inner: hyper_util::client::legacy::Error) -> Self {
        tracing::error!("hyper_util::client::legacy::Error {:?}", inner);
        println!("hyper_util::client::legacy::Error {:?}", inner);
        ErrorMsg {
            title: ERR.to_string(),
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            _type: None,
            detail: None,
            instance: None,
            code: None,
            errors: vec![],
        }
    }
}

impl From<std::string::FromUtf8Error> for ErrorMsg {
    fn from(inner: std::string::FromUtf8Error) -> Self {
        tracing::error!("FromUtf8Error {:?}", inner);
        println!("FromUtf8Error {:?}", inner);
        ErrorMsg {
            title: ERR.to_string(),
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            _type: None,
            detail: None,
            instance: None,
            code: None,
            errors: vec![],
        }
    }
}

impl From<serde_json::Error> for ErrorMsg {
    fn from(inner: serde_json::Error) -> Self {
        tracing::error!("serde_json::Error {:?}", inner);
        println!("serde_json::Error {:?}", inner);
        ErrorMsg {
            title: ERR.to_string(),
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            _type: None,
            detail: None,
            instance: None,
            code: None,
            errors: vec![],
        }
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for ErrorMsg {
    fn from(inner: Box<dyn std::error::Error + Send + Sync>) -> Self {
        tracing::error!("Box<dyn StdError + Send + Sync> {:?}", inner);
        println!("Box<dyn StdError + Send + Sync> {:?}", inner);
        ErrorMsg {
            title: ERR.to_string(),
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            _type: None,
            detail: None,
            instance: None,
            code: None,
            errors: vec![],
        }
    }
}

impl From<hyper::Error> for ErrorMsg {
    fn from(inner: hyper::Error) -> Self {
        tracing::error!("hyper::Error error {:?}", inner);
        println!("hyper::Error error {:?}", inner);
        ErrorMsg {
            title: ERR.to_string(),
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            _type: None,
            detail: None,
            instance: None,
            code: None,
            errors: vec![],
        }
    }
}

impl From<serde_urlencoded::ser::Error> for ErrorMsg {
    fn from(inner: serde_urlencoded::ser::Error) -> Self {
        tracing::error!("serde_urlencoded::ser::Error error {:?}", inner);
        println!("serde_urlencoded::ser::Error error {:?}", inner);
        ErrorMsg {
            title: ERR.to_string(),
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            _type: None,
            detail: None,
            instance: None,
            code: None,
            errors: vec![],
        }
    }
}

impl From<BorrowError> for ErrorMsg {
    fn from(inner: BorrowError) -> Self {
        tracing::error!("BorrowError::Error error {:?}", inner);
        println!("BorrowError::Error error {:?}", inner);
        ErrorMsg {
            title: ERR.to_string(),
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            _type: None,
            detail: None,
            instance: None,
            code: None,
            errors: vec![],
        }
    }
}

impl IntoResponse for ErrorMsg {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.title,
        }));

        let status = match StatusCode::from_u16(self.status) {
            Ok(status) => status,
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, body).into_response()
    }
}
