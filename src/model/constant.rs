use std::{
    env,
    sync::{LazyLock, RwLock},
};

use crate::auth::OauthKeySmall;

pub static AUD: LazyLock<String> = LazyLock::new(|| match env::var("AUD") {
    Ok(val) => val,
    Err(_e) => {
        panic!("could not find AUD")
    }
});

pub static AUTHORITY_URL: LazyLock<String> = LazyLock::new(|| match env::var("AUTHORITY_URL") {
    Ok(val) => val,
    Err(_e) => {
        panic!("could not find AUTHORITY_URL")
    }
});


#[cfg(feature = "opentelemetry")]
pub static OTEL_EXPORTER_OTLP_PROTOCOL: LazyLock<opentelemetry_otlp::Protocol> = LazyLock::new(|| match env::var("OTEL_EXPORTER_OTLP_PROTOCOL") {
    Ok(val) => {
        match val.as_str() {
            "grpc" => opentelemetry_otlp::Protocol::Grpc,
            "http/json" => opentelemetry_otlp::Protocol::HttpJson,
            "http/protobuf" => opentelemetry_otlp::Protocol::HttpBinary,
            _ => panic!("{} is not a supported value for OTEL_EXPORTER_OTLP_PROTOCOL. Choose: grpc, http/protobuf, http/json", val)
        }
    },
    Err(_e) => {
        panic!("could not find OTEL_EXPORTER_OTLP_PROTOCOL")
    }
});


#[cfg(feature = "opentelemetry")]
pub static OTEL_EXPORTER_OTLP_ENDPOINT: LazyLock<String> = LazyLock::new(|| match env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
    Ok(val) => val,
    Err(_e) => {
        panic!("could not find OTEL_EXPORTER_OTLP_ENDPOINT")
    }
});


pub static ISS: LazyLock<String> = LazyLock::new(|| match env::var("ISS") {
    Ok(val) => val,
    Err(_e) => {
        panic!("could not find ISS")
    }
});

pub static PROD: LazyLock<String> = LazyLock::new(|| match env::var("PROD") {
    Ok(val) => val,
    Err(_e) => {
        panic!("could not find PROD")
    }
});

pub static VOLUME_LOG: LazyLock<String> = LazyLock::new(|| match env::var("VOLUME_LOG") {
    Ok(val) => val,
    Err(_e) => {
        panic!("could not find VOLUME_LOG")
    }
});

pub fn kid_ne_rwlock() -> &'static RwLock<Vec<OauthKeySmall>> {
    static KID_NE_RWLOCK: RwLock<Vec<OauthKeySmall>> = RwLock::new(vec![]);
    &KID_NE_RWLOCK
}

//pub static MAX_BODY_SIZE: usize = 50000000;
