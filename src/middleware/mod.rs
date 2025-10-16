#[cfg(feature = "opentelemetry")]
mod opentelemetry;

#[cfg(feature = "opentelemetry")]
pub use opentelemetry::*;
