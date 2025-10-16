// This module provides utilities to set up OpenTelemetry tracing using the OTLP exporter.
// It configures the tracer provider, resource attributes, and integrates with tracing-subscriber.
use opentelemetry::trace::TracerProvider;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use std::{error::Error, sync::OnceLock};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};
use opentelemetry_otlp::SpanExporter;


fn init_tracer_provider() -> SdkTracerProvider{
    let exporter: SpanExporter = match *crate::model::OTEL_EXPORTER_OTLP_PROTOCOL {
        Protocol::Grpc => {
            SpanExporter::builder()
                .with_tonic()
                .with_endpoint(crate::model::OTEL_EXPORTER_OTLP_ENDPOINT.as_str())
                .build()
                .expect("Failed to create span exporter")
        },
        Protocol::HttpBinary => {
            SpanExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(crate::model::OTEL_EXPORTER_OTLP_ENDPOINT.as_str())
                .build()
                .expect("Failed to create span exporter")
        },
        Protocol::HttpJson => {
            SpanExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpJson)
                .with_endpoint(crate::model::OTEL_EXPORTER_OTLP_ENDPOINT.as_str())
                .build()
                .expect("Failed to create span exporter")
        },
    };
    
    let provider = SdkTracerProvider::builder()
        .with_resource(Resource::builder()
        .with_service_name("sdk-backend").build())
        .with_id_generator(opentelemetry_sdk::trace::RandomIdGenerator::default())
        .with_batch_exporter(exporter)
        .build();
        
    //global::set_text_map_propagator(TraceContextPropagator::new());
    //global::set_tracer_provider(provider);
    provider
}

pub fn init_tracing_opentelemetry() -> SdkTracerProvider {
    let tracer_provider = init_tracer_provider();
    global::set_tracer_provider(tracer_provider.clone());

    //let tracer = global::tracer("tracer-name");
    let tracer = tracer_provider.tracer("sdk-backend");


    let filter = EnvFilter::try_from_default_env()
    .unwrap_or_else(|_| "error,opentelemetry=error".parse().unwrap());

    let fmt_layer = tracing_subscriber::fmt::layer()
        .event_format(
            tracing_subscriber::fmt::format()
                .with_target(false)
                .with_level(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_timer(tracing_subscriber::fmt::time::ChronoLocal::rfc_3339()),
        )
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_filter(filter);

    let otel_layer = OpenTelemetryLayer::new(tracer);
    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    tracer_provider
}


/* 
fn init_logs() -> SdkLoggerProvider {
    // Setup tracerprovider with stdout exporter
    // that prints the spans to stdout.
    let logger_provider = SdkLoggerProvider::builder()
        .with_simple_exporter(LogExporter::default())
        .build();
    let otel_layer = OpenTelemetryTracingBridge::new(&logger_provider);
    tracing_subscriber::registry()
        .with(otel_layer)
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .init();

    logger_provider
}
*/
