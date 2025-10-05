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
