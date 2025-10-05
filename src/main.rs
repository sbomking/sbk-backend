//#![allow(unused)] // silence unused warnings while exploring (to comment out)
mod auth;
mod client;
mod error;
mod facade;
mod model;
mod service;
mod tests;
mod util;

use model::AppState;
use service::{health_router, product_line_router, product_router};
use tokio::net::TcpListener;

use axum::{
    Router,
    body::Bytes,
    error_handling::HandleErrorLayer,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use std::env;

use std::{borrow::Cow, fs, sync::Arc, time::Duration};
use tower::{BoxError, ServiceBuilder};
use tracing::Span;

async fn create_file(filename: &str) -> Result<fs::File, std::io::Error> {
    let file_path = model::VOLUME_LOG.to_string() + filename;
    println!("file_path {:?}", file_path);
    //let file = File::create(file_path);
    let file = fs::OpenOptions::new()
        .read(true)
        .append(true)
        //.write(true)
        .create(true)
        .open(file_path);
    file
}

#[tokio::main]
async fn main() {
    let file = create_file("debug.log").await;
    let file = match file {
        Ok(file) => file,
        Err(error) => panic!("Error: {:?}", error),
    };
    tracing_subscriber::fmt().with_writer(Arc::new(file)).init();

    let connection_env = match env::var("DATABASE_CONNECTION") {
        Ok(val) => val,
        Err(e) => {
            tracing::error!("could not find DATABASE_CONNECTION : {}", e);
            println!("could not find DATABASE_CONNECTION {:?}", e);
            panic!("could not find {}: {}", "DATABASE_CONNECTION", e)
        }
    };

    let state = AppState {
        pool: match sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(60))
            .idle_timeout(Duration::from_secs(300))
            .connect(&connection_env)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("could not connect to the DATABASE: {:?}", e);
                println!("could not connect to the DATABASE {:?}", e);
                panic!("could not connect to the DATABASE: {:?}", e)
            }
        },
    };

    //let state = AppState { pool };

    let app = Router::new()
        .merge(health_router())
        .merge(product_line_router())
        .merge(product_router())
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                // Handle errors from middleware
                .layer(HandleErrorLayer::new(handle_error))
                .load_shed()
                .concurrency_limit(1024)
                .timeout(Duration::from_secs(30))
                .layer(
                    tower_http::trace::TraceLayer::new_for_http()
                        .make_span_with(|request: &Request<_>| {
                            // Log the matched route's path (with placeholders not filled in).
                            // Use request.uri() or OriginalUri if you want the real path.
                            let matched_path = request
                                .extensions()
                                .get::<axum::extract::MatchedPath>()
                                .map(axum::extract::MatchedPath::as_str);

                            tracing::info_span!(
                                "http_request",
                                method = ?request.method(),
                                matched_path,
                                some_other_field = tracing::field::Empty,
                            )
                        })
                        .on_request(|_request: &Request<_>, _span: &Span| {
                            // You can use `_span.record("some_other_field", value)` in one of these
                            // closures to attach a value to the initially empty field in the info_span
                            // created above.
                            //tracing::error!("on_request! on");
                        })
                        .on_response(|_response: &Response, _latency: Duration, _span: &Span| {
                            //tracing::error!("on_response on {} ms", _latency.as_millis());
                        })
                        .on_body_chunk(|_chunk: &Bytes, _latency: Duration, _span: &Span| {
                            //tracing::error!("on_body_chunk: {} ms", _latency.as_millis());
                        })
                        .on_eos(
                            |_trailers: Option<&hyper::HeaderMap>,
                             _stream_duration: Duration,
                             _span: &Span| {
                                tracing::error!("on_eos: {} ms", _stream_duration.as_millis());
                            },
                        )
                        .on_failure(
                            |_error: tower_http::classify::ServerErrorsFailureClass,
                             _latency: Duration,
                             _span: &Span| {
                                tracing::error!(
                                    "err: {} on {} ms",
                                    _error.to_string(),
                                    _latency.as_millis()
                                );
                            },
                        ),
                )
                .into_inner(),
        );

    let listener = TcpListener::bind("0.0.0.0:5002").await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

async fn handle_error(error: BoxError) -> impl IntoResponse {
    if error.is::<tower::timeout::error::Elapsed>() {
        return (StatusCode::REQUEST_TIMEOUT, Cow::from("request timed out"));
    }

    if error.is::<tower::load_shed::error::Overloaded>() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Cow::from("service is overloaded, try again later"),
        );
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Cow::from(format!("Unhandled internal error: {}", error)),
    )
}
