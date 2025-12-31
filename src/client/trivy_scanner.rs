pub mod trivy {
    tonic::include_proto!("trivy.rpc.v1");
}

use core::panic;
use std::{any::Any, collections::HashMap, str::FromStr};

use axum::http::HeaderValue;
use hyper::Uri;
use hyper_util::client::legacy::connect::HttpConnector;
use packageurl::PackageUrl;
use prost::Message;
use rustls_pki_types::pem::PemObject;
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::{Service, ServiceExt};
use trivy::{
    ArtifactInfo, BlobInfo, CustomResource, DeleteBlobsRequest, DetectedLicense,
    DetectedMisconfiguration, LicenseCategory, MissingBlobsRequest, MissingBlobsResponse, Os,
    Package, PutArtifactRequest, PutBlobRequest, PutResponse, SecretFinding, cache_client,
};

use crate::{
    client::{
        get_hyper_client, get_hyper_client_unsecure,
        trivy::{
            Application, Layer, LicenseFile, Misconfiguration, PackageInfo, PkgIdentifier, Secret,
            cache_server::Cache,
        },
    },
    error::ErrorMsg,
    model::{
        CdxBom, HashAlg, LicenseChoiceUrl, TRIVY_PROXY_PK, Vulnerability,
        VulnerabilityItemAffectsItemVersionsVariant0,
    },
};
//use api::{publisher_client::PublisherClient, ListTopicsRequest};

#[derive(Clone, PartialEq, Eq, /*Hash,*/ ::prost::Message)]
pub struct TrivyErrorResponse {
    #[prost(string, tag = "1")]
    pub code: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub msg: ::prost::alloc::string::String,
    //#[prost(map = "string, string", tag = "3")]
    //pub meta: prost::alloc::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
    #[prost(map = "string, string", tag = "3")]
    pub meta: HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
}

/**
 * Client integration with a trivy server.
 */
pub async fn scan_cdx(
    cdx: &CdxBom,
    lang: &String,
) -> core::result::Result<Vec<crate::model::bom::Vulnerability>, ErrorMsg> {
    let blob_infos: Vec<BlobInfo> = match cdx.to_trivy_blob_info() {
        Ok(blobs) => blobs,
        Err((validation_error, arg_map_opt)) => {
            return Err(ErrorMsg {
                title: crate::util::get_message(lang, validation_error, &arg_map_opt),
                status: hyper::StatusCode::CONFLICT.as_u16(),
                _type: None,
                detail: None,
                instance: None,
                code: None,
                errors: vec![],
            });
        }
    };

    let vulnerabilities: Vec<crate::model::bom::Vulnerability> =
        scan_blob_infos(&blob_infos).await?;
    Ok(vulnerabilities)
}

pub async fn scan_blob_infos(
    blob_infos: &Vec<BlobInfo>,
) -> core::result::Result<Vec<crate::model::bom::Vulnerability>, ErrorMsg> {
    let mut vulnerabilities: Vec<Vulnerability> = vec![];

    let results: Vec<trivy::Result> = vec![];

    for blob_info in blob_infos {
        //let diff_id = rand::distr::SampleString::sample_string(&rand::distr::Alphanumeric, &mut rand::rng(), 16);
        //TODO diff_id sha256

        // Print the full content of blob_info in JSON format
        //let blob_info_json = serde_json::to_string_pretty(&blob_info).unwrap();
        //println!("BlobInfo JSON: {}", blob_info_json);

        let random_string = rand::distr::SampleString::sample_string(
            &rand::distr::Alphanumeric,
            &mut rand::rng(),
            16,
        );
        let mut diff_id_hex = Sha256::new();
        diff_id_hex.update(random_string);
        let diff_id: String = format!("sha256:{:X}", diff_id_hex.finalize());

        //String::from("sha256:") + &diff_id, //+random sha256,
        let put_blob_http: PutBlobRequest = PutBlobRequest {
            blob_info: Some(blob_info.clone()),
            diff_id: blob_info.diff_id.clone(), // diff_id.clone()
        };

        //let str = String::from_utf8(put_blob_http.encode_to_vec())?;
        //println!("put_blob_http bytes u8 {:?} ", str);

        // Serialize the message to a byte array using Prost
        let mut buf = Vec::new();
        prost::Message::encode(&put_blob_http, &mut buf)?;

        // Print the buf to a JSON format
        //let json_str = serde_json::to_string_pretty(&put_blob_http).unwrap();
        //println!("PutBlobRequest JSON: {}", json_str);
        println!("Body bytes {:?} ", put_blob_http);

        //https://github.com/twitchtv/twirp?tab=readme-ov-file
        let prod = crate::model::PROD.as_str();
        let request = hyper::Request::builder()
            .method("POST")
            //.uri(String::from("https://127.0.0.1:10001/twirp/trivy.cache.v1.Cache/PutBlob"))
            .uri(String::from(
                "http://127.0.0.1:10000/twirp/trivy.cache.v1.Cache/PutBlob",
            ))
            .header("Content-Type", "application/protobuf")
            .header("Accept", "application/protobuf")
            .header("Host", "127.0.0.1")
            .header("Content-Length", buf.len().to_string())
            .header("Twirp-Version", "v8.1.3")
            .version(hyper::Version::HTTP_11)
            .body(axum::body::Body::from(buf))?;
        //.body(axum::body::Body::from(serde_json::to_vec(&buf)?))?;
        //.body(axum::body::Body::empty())?;

        /*let host = url.host().expect("uri has no host");
        let port = url.port_u16().unwrap_or(80);
        let addr = format!("{}:{}", host, port);
        */
        let stream = tokio::net::TcpStream::connect(String::from("127.0.0.1:10000")).await?;
        let io = hyper_util::rt::TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                println!("Connection failed: {:?}", err);
            }
        });
        //Working for HTTP 1.1
        let mut response = sender.send_request(request).await?;

        //get_hyper_client
        //let mut response = get_hyper_client()?.ready().await?.call(request).await?;
        //let mut response = get_hyper_client_unsecure().await?.ready().await?.call(request).await?;
        /*
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
        */

        /*let keys_str: String =*/
        if response.status() != hyper::StatusCode::OK {
            println!("update_oidc_key response: {} ", response.status());
            //let body_bytes = axum::body::to_bytes(response.into_body(), MAX_BODY_SIZE).await?;
            let body_bytes = http_body_util::BodyExt::collect(response.into_body())
                .await?
                .to_bytes();
            println!("Body bytes {:X} ", body_bytes);

            //let trivy_error: TrivyErrorResponse = prost::Message::decode(&body_bytes[..])?;
            //println!("trivy_error code {}", trivy_error.code);
            //println!("trivy_error msg {}", trivy_error.msg);

            //7B22636F6465223A226D616C666F726D6564222C226D7367223A227468652070726F746F627566207265717565737420636F756C64206E6F74206265206465636F646564227D
            //{"code":"malformed","msg":"the prototype request could not be decoded"}

            //let str = String::from_utf8(body_bytes.to_vec())?;
            //tracing::info!("update_oidc_key response body {} ", str);
            //println!("update_oidc_key response body {} ", str);
            return Err(ErrorMsg {
                title: "Impossible to fetch token".to_string(),
                status: hyper::StatusCode::UNAUTHORIZED.as_u16(),
                _type: None,
                detail: None,
                instance: None,
                code: None,
                errors: vec![],
            });
        } else {
            //tracing::info!("else update_oidc_key response {} ", response.status());
            //println!("else update_oidc_key response: {} ", response.status());
            //let body_bytes = axum::body::to_bytes(response.into_body(), MAX_BODY_SIZE).await?;
            //let body_bytes = http_body_util::BodyExt::collect(response.into_body()).await?.to_bytes();
            //let str = String::from_utf8(body_bytes.to_vec())?;

            //let body_bytes = http_body_util::BodyExt::collect(response.into_body()).await?.to_bytes();
            //let scan_response: ScanResponse = prost::Message::decode(&body_bytes[..])?;

            //tracing::info!("else update_oidc_key Body bytes {} ", str);
            //println!("Body bytes {} ", str);
        };
        //println!("put_blob response {:?}", keys_str);

        //vuln,misconfig,secret,license
        let scan_blob: crate::client::trivy::ScanRequest = crate::client::trivy::ScanRequest {
            target: blob_info.diff_id.clone().clone(),
            artifact_id: blob_info.diff_id.clone().clone(),
            blob_ids: vec![blob_info.diff_id.clone().clone().clone()],

            options: Some(crate::client::trivy::ScanOptions {
                pkg_types: vec!["library".to_string(), "os".to_string()],
                scanners: vec!["vuln".to_string(), "sbom".to_string()],
                license_categories: HashMap::new(),
                include_dev_deps: false,
                pkg_relationships: vec![
                    "unknown".to_string(),
                    "root".to_string(),
                    "workspace".to_string(),
                    "direct".to_string(),
                    "indirect".to_string(),
                ],
                distro: None,
                vuln_severity_sources: vec!["auto".to_string()],
                license_full: false,
            }),
        };

        let mut buf = Vec::new();
        prost::Message::encode(&scan_blob, &mut buf)?;
        let request = hyper::Request::builder()
            .method("POST")
            .uri(String::from(
                "http://127.0.0.1:10000/twirp/trivy.scanner.v1.Scanner/Scan",
            ))
            .header("Content-Type", "application/protobuf")
            .header("Host", "127.0.0.1")
            .header("Content-Length", buf.len().to_string())
            .version(hyper::Version::HTTP_11)
            .body(axum::body::Body::from(buf))?;

        let mut response = sender.send_request(request).await?;

        if response.status() != hyper::StatusCode::OK {
            println!("Scan response: {} ", response.status());
            //let body_bytes = axum::body::to_bytes(response.into_body(), MAX_BODY_SIZE).await?;
            let body_bytes = http_body_util::BodyExt::collect(response.into_body())
                .await?
                .to_bytes();
            let str = String::from_utf8(body_bytes.to_vec())?;
            tracing::info!("Scan response body {} ", str);
            println!("Scan response body {} ", str);
            return Err(ErrorMsg {
                title: "Impossible to fetch token".to_string(),
                status: hyper::StatusCode::UNAUTHORIZED.as_u16(),
                _type: None,
                detail: None,
                instance: None,
                code: None,
                errors: vec![],
            });
        } else {
            //tracing::info!("else Scan response {} ", response.status());
            //println!("else Scan response: {} ", response.status());

            //let body_bytes = axum::body::to_bytes(response.into_body(), MAX_BODY_SIZE).await?;
            let body_bytes = http_body_util::BodyExt::collect(response.into_body())
                .await?
                .to_bytes();
            //println!("Body bytes {:X} ", body_bytes);
            //let mut buf: &[u8] = &body_bytes.to_vec();
            //println!("Body bytes u8 {:X} ", buf);
            //let scan_response: ScanResponse = prost::Message::decode(buf)?;
            let scan_response: crate::client::trivy::ScanResponse =
                prost::Message::decode(&body_bytes[..])?;

            for result in scan_response.results {
                tracing::info!("SCAN result {} ", result.target);
                println!("SCAN result {} ", result.target);
                for misconf in &result.misconfigurations {
                    println!("  Misconfiguration ID: {}", misconf.id);
                    println!("  primary_url: {}", misconf.primary_url);
                    println!("  Message: {}", misconf.message);
                }
                for package in &result.packages {
                    println!("  package name: {}", package.name);
                    //println!("  package digest: {}", package.digest);
                }
                for custom_resource in &result.custom_resources {
                    println!("  custom_resource file_path: {}", custom_resource.file_path);
                }

                for vulnerability in &result.vulnerabilities {
                    //println!("vulnerability.description: {}", vulnerability.description);

                    match vulnerability.to_cdx_vulnerability() {
                        Ok(cdx_vulnerability) => vulnerabilities.push(cdx_vulnerability),
                        Err(error) => {
                            println!("to_cdx_vulnerability error: {}", error.title);
                            tracing::error!("to_cdx_vulnerability {} ", error.title);
                            return Err(error);
                        }
                    }
                }
            }
            //let str = String::from_utf8(body_bytes.to_vec())?;
            //tracing::info!("else Scan Body bytes {} ", str);
            //println!("Body bytes {} ", str);
            //str
        };
        //println!("Scan response {:?}", keys_str);
        //Scanner::scan(&'life0 self, request)

        /*
        let put_blob: PutBlobRequest = PutBlobRequest {
            blob_info: Some(blob_info.clone()),
            diff_id: String::from("sha256:"), //+random sha256,
        };

        let put_blob_request = tonic::Request::new(put_blob);

        let my_trivy = MyTrivyImpl {};

        match my_trivy.put_blob(put_blob_request).await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("calling put_blob failed: {:?}", e);
                println!("calling put_blob failed {:?}", e);
                panic!("calling put_blob failed: {:?}", e)
            }
        };
        */

        //my_trivy.scan_blob_infos(blob_infos).await?;

        //let blob_scan_result = Scanner::scan(&'life0 self, request)
        //results.append(blob_scan_result);
    }

    Ok(vulnerabilities)
}

pub struct MyTrivyImpl {}

#[tonic::async_trait]
impl Cache for MyTrivyImpl {
    /**
     *  rpc PutBlob(PutBlobRequest) returns (google.protobuf.Empty);
     */
    async fn put_blob(
        &self,
        request: tonic::Request<PutBlobRequest>,
    ) -> std::result::Result<tonic::Response<()>, tonic::Status> {
        //let endpoint = "http://[::1]:10001";
        let endpoint = "http://[::1]:10000";

        match tonic::transport::Channel::from_static(endpoint)
            .connect()
            .await
        {
            Ok(channel) => {
                println!("✅ Successfully connected to {}", &endpoint);
                // You can now use `channel` to create your client

                //calling put_blob failed: Status { code: Unknown, message: "h2 protocol error: http2 error",
                // source: Some(tonic::transport::Error(Transport, hyper::Error(Http2, Error { kind: GoAway(b"", FRAME_SIZE_ERROR, Library) }))) }
                //let mut client = cache_client::CacheClient::new(channel);
                //let response = client.put_blob(request).await?;
                //println!("RESPONSE={:?}", response);
            }
            Err(e) => {
                println!("❌ Failed to connect: {}", e);
            }
        };

        match tonic::transport::Endpoint::from_static(endpoint)
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .http2_keep_alive_interval(std::time::Duration::from_secs(30))
            .keep_alive_while_idle(true)
            .connect()
            .await
        {
            Ok(channel) => {
                println!("✅ HTTP2 Successfully connected to {}", &endpoint);
                // You can now use `channel` to create your client
                /*
                let (stream, _) = listener.accept().await?;
                // Use an adapter to access something implementing `tokio::io` traits as if they implement
                // `hyper::rt` IO traits.
                let io = TokioIo::new(stream);

                // Spin up a new task in Tokio so we can continue to listen for new TCP connection on the
                // current task without waiting for the processing of the HTTP/2 connection we just received
                // to finish
                tokio::task::spawn(async move {
                    // Handle the connection from the client using HTTP/2 with an executor and pass any
                    // HTTP requests received on that connection to the `hello` function
                    if let Err(err) = http2::Builder::new(TokioExecutor)
                        .serve_connection(io, service_fn(hello))
                        .await
                    {
                        eprintln!("Error serving connection: {}", err);
                    }
                });
                */
                //let test = hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());

                //calling put_blob failed: Status { code: Unknown, message: "h2 protocol error: http2 error", source: Some(tonic::transport::Error(Transport, hyper::Error(Http2, Error { kind: GoAway(b"", FRAME_SIZE_ERROR, Library) }))) }
                //let mut client = cache_client::CacheClient::new(channel);
                //let response = client.put_blob(request).await?;
                //println!("RESPONSE={:?}", response);
            }
            Err(e) => {
                println!("❌ HTTP2 Failed to connect: {}", e);
            }
        };

        match tonic::transport::Channel::from_static(endpoint)
            .connect()
            .await
        {
            Ok(channel) => {
                println!("✅ Successfully connected to {}", &endpoint);
                // You can now use `channel` to create your client
            }
            Err(e) => {
                println!("❌ Failed to connect: {}", e);
            }
        };

        /*

        let endpoint = tonic::transport::Endpoint::from_static(&endpoint).
            .tls_config(ClientTlsConfig::new())?; // configure TLS as needed
        let channel = endpoint.connect().await?;
        */

        /*********************************************************
         ********************    HTTPS        ********************
         *********************************************************
         */

        let _ = rustls::crypto::ring::default_provider().install_default();

        let certs = rustls_pki_types::CertificateDer::from_pem_slice(
            &String::from(TRIVY_PROXY_PK.as_str()).as_bytes(),
        )
        .expect("Failed to parse PEM certificate");

        //let certs = rustls_pemfile::certs(&String::from(TRIVY_PROXY_PK.as_str()).as_bytes()).collect::<Result<Vec<_>, _>>()?;

        println!("TRIVY_PROXY_PK={:?}", String::from(TRIVY_PROXY_PK.as_str()));

        let mut roots = rustls::RootCertStore::empty();
        match roots.add(certs) {
            Ok(_) => {}
            Err(_) => panic!("OLOLOL ERROR"),
        }
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        // if you want to completely disable cert-verification, use this
        let mut dangerous_config = rustls::ClientConfig::dangerous(&mut tls);
        dangerous_config.set_certificate_verifier(std::sync::Arc::new(
            crate::client::NoCertificateVerification {},
        ));

        /**
         * New try
         */
        /*
         let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http2()
            .build();
        */
        let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
        http.enforce_http(false);

        // We have to do some wrapping here to map the request type from
        // `https://example.com` -> `https://[::1]:50051` because `rustls`
        // doesn't accept ip's as `ServerName`.

        let connector = tower::ServiceBuilder::new()
            .layer_fn(move |s| {
                let tls = tls.clone();

                hyper_rustls::HttpsConnectorBuilder::new()
                    .with_tls_config(tls)
                    .https_or_http()
                    .enable_http2()
                    .wrap_connector(s)
            })
            // Since our cert is signed with `example.com` but we actually want to connect
            // to a local server we will override the Uri passed from the `HttpsConnector`
            // and map it to the correct `Uri` that will connect us directly to the local server.
            .map_request(|_| Uri::from_static("https://[::1]:10001"))
            .service(http);

        /*
        let stream = TcpStream::connect(addr).await?;
        let io = TokioIo::new(stream);
        hyper::client::conn::http2::handshake(exec, io)
        */
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector);

        //get_hyper_client()?.ready().await?.call(request).await?

        let uri = hyper::Uri::from_static("https://127.0.0.1:10001");

        let mut cc = cache_client::CacheClient::with_origin(client, uri);

        /**
        * Some(hyper_util::client::legacy::Error(Connect, Custom { kind: Other, error: Custom { kind: InvalidData, error: InvalidCertificate(Other(OtherError(CaUsedAsEndEntity))) } })) }
           calling put_blob failed Status { code: Unknown, message: "client error (Connect)", source: Some(hyper_util::client::legacy::Error(Connect, Custom
           { kind: Other, error: Custom { kind: InvalidData, error: InvalidCertificate(Other(OtherError(CaUsedAsEndEntity))) } })) }
        */
        let response = cc.put_blob(request).await?;
        println!("RESPONSE={:?}", response);

        // THE SOLUTION IS THIS: Nvm, the HTTP server exposed by Trivy also supports application/protobuf payloads. Protobuf can be used without gRPC: https://twitchtv.github.io/twirp/docs/proto_and_json.html
        //TODO use application/protobuf

        /**
         * END NEW TRY
         */

        /**
         * OLD CODE
         */
        /*
        let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
        http.enforce_http(false);
        // We have to do some wrapping here to map the request type from
        // `https://example.com` -> `https://[::1]:50051` because `rustls`
        // doesn't accept ip's as `ServerName`.
        let connector = tower::ServiceBuilder::new()
            .layer_fn(move |s| {
                let tls = tls.clone();

                hyper_rustls::HttpsConnectorBuilder::new()
                    //.with_tls_config(tls)
                    .with_tls_config(match crate::client::get_rustls_config_dangerous() {
                        Ok(conf) => conf,
                        Err(_) => tls,
                    })
                    .https_or_http()
                    .enable_http2()
                    //.enable_http1()
                    .wrap_connector(s)
            })
            // Since our cert is signed with `example.com` but we actually want to connect
            // to a local server we will override the Uri passed from the `HttpsConnector`
            // and map it to the correct `Uri` that will connect us directly to the local server.
            .map_request(|_| hyper::Uri::from_static("https://[::1]:10001"))
            /* .map_request(|mut req: hyper::Request<_> | {
                *req.uri_mut() = hyper::Uri::builder()
                    .scheme("https")
                    .authority("[::1]:10001")
                    .path_and_query(req.uri().path_and_query().unwrap().clone())
                    .build()
                    .unwrap();
                req.headers_mut().insert(
                    hyper::header::HOST,
                    HeaderValue::from_static("example.com"),
                );
                req
            })*/
            .service(http);

        let hyper_client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector);

        let uri = hyper::Uri::from_static("https://127.0.0.1:10001");

        let mut cc = cache_client::CacheClient::with_origin(hyper_client, uri);
        */
        //let response = cc.put_blob(request).await?;

        /**
         * END OLD CODE
         */

        //let _ = response.into_inner();
        //Ok(tonic::Response::new(()))
        //println!("RESPONSE={:?}", response);

        /**
         * curl -X POST -H 'Content-Type: application/grpc' -H 'Accept: application/grpc' --data-binary '@request.bin' 'http://127.0.0.1:10000/trivy.rpc.v1.Cache/PutBlob'
         *
         * gives 404 page not found.
         */

        /**In HTTPS, it looks like the trivy-server reply without an h2 request. Either we have to pass some header or it is http 1.0.
        * https://github.com/kubernetes/ingress-nginx/issues/4323
        * 8#38: *4 upstream sent too large http2 frame: 4740180 while reading response header from upstream,
        client: 10.89.0.12, server: , request: "POST /trivy.rpc.v1.Cache/PutBlob HTTP/2.0", upstream: "grpc://127.0.0.1:10000", host: "127.0.0.1:10001"
        */
        /* correct code
        let mut cc = cache_client::CacheClient::with_origin(hyper_client, uri);
        let response = cc.put_blob(request).await?;

        println!("RESPONSE={:?}", response);
        */


        /*
        let client = match crate::client::get_hyper_client_with_custom_certs(&String::from(TRIVY_PROXY_PK.as_str())) {
            Ok(client) => client,
            Err(_) => panic!("OMG"),
        };
        let uri = hyper::Uri::from_static(endpoint);
        let mut client = cache_client::CacheClient::with_origin(client, uri);

         //TRIVY_PROXY_PK
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
        */
        //cache_client::CacheClient::with_origin(inner, origin)
        let endpoint = "http://[::1]:10000";
        let mut client = match cache_client::CacheClient::connect(endpoint).await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("could not connect to the TRIVY SERVER: {:?}", e);
                println!("could not connect to the TRIVY SERVER {:?}", e);
                panic!("could not connect to the TRIVY SERVER: {:?}", e)
            }
        };
        /*
        //calling put_blob failed: Status { code: Unknown, message: "h2 protocol error: http2 error", source: Some(tonic::transport::Error(Transport, hyper::Error(Http2, Error { kind: GoAway(b"", FRAME_SIZE_ERROR, Library) }))) }
        let response = client.put_blob(request).await?;

        println!("RESPONSE={:?}", response);
        */

        /*
        let put_blob = request.into_inner();
        // Access fields from the request
        let diff_id = put_blob.diff_id;
        let blob_info = put_blob.blob_info;

        // Example: Log or process the blob
        println!("Received blob with diff_id: {}", diff_id);

        if let Some(info) = blob_info {
            println!("Blob digest: {}", info.digest);
            println!("Blob size: {}", info.size);
            // You can store it, validate it, etc.
        } else {
            return Err(tonic::Status::invalid_argument("Missing blob_info"));
        }
        */

        // Return an empty response
        Ok(tonic::Response::new(()))
    }

    /**
     * rpc PutArtifact(PutArtifactRequest) returns (google.protobuf.Empty);
     */
    async fn put_artifact(
        &self,
        request: tonic::Request<PutArtifactRequest>,
    ) -> std::result::Result<tonic::Response<()>, tonic::Status> {
        let req = request.into_inner();
        println!("Received artifact_id: {}", req.artifact_id);
        //println!("Artifact schema version: {}", req.artifact_info.schema_version);

        // TODO: Store or process the artifact_info as needed

        Ok(tonic::Response::new(()))
    }

    /**
     * rpc MissingBlobs(MissingBlobsRequest) returns (MissingBlobsResponse);
     */
    async fn missing_blobs(
        &self,
        request: tonic::Request<MissingBlobsRequest>,
    ) -> std::result::Result<tonic::Response<MissingBlobsResponse>, tonic::Status> {
        let req = request.into_inner();
        println!(
            "Checking missing blobs for artifact_id: {}",
            req.artifact_id
        );

        // TODO: Replace with actual logic to check which blobs are missing
        let missing_blob_ids = req
            .blob_ids
            .into_iter()
            .filter(|id| id.contains("missing")) // Dummy logic
            .collect();

        let response = MissingBlobsResponse {
            missing_artifact: false,
            missing_blob_ids,
        };

        Ok(tonic::Response::new(response))
    }

    /**
     * rpc DeleteBlobs(DeleteBlobsRequest) returns (google.protobuf.Empty);
     */
    async fn delete_blobs(
        &self,
        request: tonic::Request<DeleteBlobsRequest>,
    ) -> std::result::Result<tonic::Response<()>, tonic::Status> {
        let req = request.into_inner();
        println!("Deleting blobs: {:?}", req.blob_ids);

        // TODO: Perform deletion logic here

        Ok(tonic::Response::new(()))
    }
}

/*
#[tokio::main]
async fn main() -> core::result::Result<(), Box<dyn std::error::Error>> {
    /*
    let mut client = GreeterClient::connect("http://[::1]:50051").await?;

    let request = tonic::Request::new(HelloRequest {
        name: "Tonic".into(),
    });

    let response = client.say_hello(request).await?;

    println!("RESPONSE={:?}", response);
    */

    Ok(())
}
*/
/*
https://protobuf-decoder.netlify.app/

0a477368613235363a333837383832613937323739336338366234356265383331323432316132346461623363323932313130613238653432393230363264316436643464613434331ad006080212120a0663656e746f731208372e362e313831301ab70612fc020a04626173681206342e322e34361a0633312e656c372a067838365f36343204626173683a06342e322e3436420633312e656c375a92010a477368613235363a6163393230383230376164616163336134386535346134646336623439633639653738633330373264326233616464376566646162663831346462323133336212477368613235363a383931363964383764626532623732626134326266626233353739633935373332326261636132386530336131653535383037363534326131633162326234616a196261736840342e322e34362d33312e656c372e7838365f36347a0647504c76332b9a018c010a44706b673a72706d2f63656e746f732f6261736840342e322e34362d33312e656c373f617263683d7838365f36342664697374726f3d63656e746f732d372e362e313831301244706b673a72706d2f63656e746f732f6261736840342e322e34362d33312e656c373f617263683d7838365f36342664697374726f3d63656e746f732d372e362e3138313012b5030a0c6f70656e73736c2d6c6962731206312e302e326b1a0631362e656c3720012a067838365f363432076f70656e73736c3a06312e302e326b420631362e656c3748015a92010a477368613235363a6163393230383230376164616163336134386535346134646336623439633639653738633330373264326233616464376566646162663831346462323133336212477368613235363a383931363964383764626532623732626134326266626233353739633935373332326261636132386530336131653535383037363534326131633162326234616a216f70656e73736c2d6c69627340312e302e326b2d31362e656c372e7838365f36347a084f70656e53534c2b9a01ac010a54706b673a72706d2f63656e746f732f6f70656e73736c2d6c69627340312e302e326b2d31362e656c373f617263683d7838365f36342664697374726f3d63656e746f732d372e362e313831302665706f63683d311254706b673a72706d2f63656e746f732f6f70656e73736c2d6c69627340312e302e326b2d31362e656c373f617263683d7838365f36342665706f63683d312664697374726f3d63656e746f732d372e362e31383130
*/
impl CdxBom {
    pub fn to_trivy_blob_info(
        &self,
    ) -> std::result::Result<Vec<BlobInfo>, (&&str, Option<HashMap<String, String>>)> {
        let mut blob_infos: Vec<BlobInfo> = vec![];

        let mut i: i32 = 0;
        //packageInfo, application, os, componentByPUrl

        match &self.components {
            Some(components) => {
                //Set the OS if it is found in the SBOM.
                let os: Option<Os> =
                    match &components.iter().find(|c| c.type_ == "operating-system") {
                        Some(os_component) => Some(Os {
                            family: os_component.name.clone(),
                            name: match &os_component.version {
                                Some(version) => version.clone(),
                                None => String::from(""),
                            },
                            eosl: false,
                            extended: false,
                        }),
                        None => None,
                    };

                for component in components {
                    println!("component.type_: {:?}", component.type_);
                    i = i + 1;
                    let mut packages: Vec<Package> = vec![];

                    let digest: Option<String> = match &component.hashes {
                        Some(hashes) => match hashes.iter().find(|h| h.alg == HashAlg::Sha256) {
                            Some(sha_256) => Some(String::from("SHA256:") + &sha_256.content),
                            None => {
                                match hashes.iter().find(|h| h.alg == HashAlg::Sha1) {
                                    Some(sha_1) => Some(String::from("SHA1:") + &sha_1.content),
                                    None => {
                                        //let mut map: HashMap<String, String> = HashMap::new();
                                        //map.insert("component_name".to_string(), component.name.clone());
                                        //return Err((&"sha256-of-component-not-provided", Some(map)));
                                        //String::from( "sha256:ac9208207adaac3a48e54a4dc6b49c69e78c3072d2b3add7efdabf814db2133b",)
                                        None
                                    }
                                }
                            }
                        },
                        None => None,
                    };
                    match &component.properties {
                        Some(properties) => {
                            for property in properties {
                                //println!("property name: {:?}", property.name);
                                match &property.value {
                                    Some(value) => {
                                        //println!("property value: {:?}", value);
                                    }
                                    None => {}
                                }
                            }
                        }
                        None => {}
                    }

                    /* Package URL.
                     * pkg:rpm/opensuse/curl@7.56.1-1.1.?arch=i386&distro=opensuse-tumbleweed
                     */
                    match &component.purl {
                        Some(purl) => {
                            let packageurl: PackageUrl = PackageUrl::from_str(purl).unwrap();
                            let package_type = packageurl.ty();
                            println!("package_type: {:?}", package_type);

                            if package_type != "" && package_type != "unknown" {
                                let name = match package_type == "cocoa"
                                    || package_type == "maven"
                                    || package_type == "gradle"
                                    || package_type == "bitnami"
                                {
                                    true => packageurl.name().to_string(),
                                    false => {
                                        let name = match &component.group {
                                            Some(group) => {
                                                group.to_string()
                                                    + &String::from("/")
                                                    + &component.name.to_string()
                                            }
                                            None => component.name.to_string(),
                                        };
                                        name
                                    }
                                };

                                let arch = match packageurl.qualifiers().get("arch") {
                                    Some(architecture) => architecture.to_string(),
                                    None => String::from("x86_64"),
                                };

                                let epoch = match packageurl.qualifiers().get("epoch") {
                                    Some(epoch) => match epoch.to_string().parse::<i32>() {
                                        Ok(val) => Some(val),
                                        Err(_e) => None,
                                    },
                                    None => None,
                                };

                                let distro = match packageurl.qualifiers().get("distro") {
                                    Some(distro) => distro.to_string(),
                                    None => String::from(""),
                                };

                                let version = match &packageurl.version() {
                                    Some(version) => version.to_string(),
                                    None => String::from(""),
                                };

                                let identifier: Option<PkgIdentifier> = match &component.bom_ref {
                                    Some(bom_reference) => Some(PkgIdentifier {
                                        purl: purl.clone(),
                                        bom_ref: bom_reference.clone(),
                                        uid: String::from(""),
                                    }),
                                    None => None,
                                };
                                /*
                                *     id: "bash@4.2.46-31.el7.x86_64"
                                name: "bash"
                                version: "4.2.46"
                                release: "31.el7"
                                */
                                let versions: Vec<&str> = version.split("-").collect();
                                let mut iter_versions = versions.iter();
                                let semver_version = match iter_versions.next() {
                                    Some(v) => v,
                                    None => "",
                                };
                                let release = match iter_versions.next() {
                                    Some(v) => v,
                                    None => "",
                                };

                                //TODO, this protobuff is missing the field 11 & 19
                                let package: Package = Package {
                                    //package_type.to_string() +
                                    id: packageurl.name().to_string()
                                        + &"@"
                                        + &version.clone()
                                        + &"."
                                        + &arch.clone(), //i.to_string(),
                                    //bash
                                    name: name.clone(), //packageurl.name().to_string(),
                                    //4.2.46
                                    version: semver_version.to_owned(),
                                    //31.el7
                                    release: release.to_owned(),
                                    epoch: epoch,
                                    arch: arch,
                                    //src_name: packageurl.name().to_string(),
                                    //src_version: version,
                                    src_name: name,
                                    src_version: semver_version.to_owned(),
                                    src_release: release.to_owned(),
                                    src_epoch: epoch,
                                    licenses: vec![String::from("GPLv3+")],
                                    file_path: None,
                                    digest: digest.clone(),
                                    dev: None,
                                    indirect: true,
                                    identifier,
                                    locations: vec![],
                                    layer: None,
                                    depends_on: vec![],
                                    maintainer: String::from(""),
                                    relationship: 0,
                                };
                                packages.push(package);
                            }
                        }
                        None => {
                            /*
                            match component.type_ == "operating-system" {
                                true => {
                                    let os_component: Os = Os {
                                        family: component.name.clone(),
                                        name: match &component.version {
                                            Some(version) => version.clone(),
                                            None => String::from(""),
                                        },
                                        eosl: false,
                                        extended: false,
                                    };
                                    os = Some(os_component)
                                }
                                false => {}
                            };
                             */
                        }
                    }

                    let applications: Vec<Application> = vec![];
                    let opaque_dirs: Vec<String> = vec![];
                    let whiteout_files: Vec<String> = vec![];
                    let misconfigurations: Vec<Misconfiguration> = vec![];

                    //let random_string = rand::distr::SampleString::sample_string(&rand::distr::Alphanumeric, &mut rand::rng(), 16);
                    //let diff_id: String = String::from("sha256:...");
                    //TODO it should be sha256:...
                    //let diff_id_hex = sha2::Sha256::digest(random_string.as_bytes());
                    //let mut diff_id_hex = Sha256::new();
                    //diff_id_hex.update(random_string);
                    //let diff_id: String = format!("{:X}", diff_id_hex.finalize());

                    let random_string = rand::distr::SampleString::sample_string(
                        &rand::distr::Alphanumeric,
                        &mut rand::rng(),
                        16,
                    );
                    let mut diff_id_hex = Sha256::new();
                    diff_id_hex.update(random_string);
                    let diff_id: String = format!("sha256:{:X}", diff_id_hex.finalize());

                    let custom_resources: Vec<CustomResource> = vec![];
                    let secrets: Vec<Secret> = vec![];

                    let licenses: Vec<LicenseFile> = match &component.licenses {
                        Some(license_choise_url) => {
                            match license_choise_url {
                                LicenseChoiceUrl::Variant0(
                                    license_choice_url_variant0_item_urls,
                                ) => {
                                    let detected_licenses: Vec<DetectedLicense> = vec![];
                                    //let license_urls: Vec<crate::model::bom::License> = license_choice_url_variant0_item_urls.iter().map(|l| l.license).collect();
                                    /*
                                    for license_urls in license_urls {
                                        let detected_license = DetectedLicense {
                                            severity: todo!(),
                                            category: todo!(),
                                            pkg_name: todo!(),
                                            file_path: todo!(),
                                            name: todo!(),
                                            confidence: license_urls,
                                            link: todo!(),
                                        }
                                    }
                                    */
                                    vec![]
                                }
                                LicenseChoiceUrl::Variant1(
                                    license_choice_url_variant1_item_licenses,
                                ) => {
                                    vec![]
                                }
                            }
                        }
                        None => vec![],
                    };
                    let size: i64 = 7;
                    let created_by: String = String::from("");

                    let package_infos: Vec<PackageInfo> = vec![PackageInfo {
                        file_path: None,
                        packages: packages,
                    }];

                    let blob_info: BlobInfo = BlobInfo {
                        schema_version: 2,
                        os: os.clone(),
                        package_infos,
                        applications,
                        misconfigurations,
                        opaque_dirs,
                        whiteout_files,
                        digest,
                        diff_id,
                        custom_resources,
                        secrets,
                        licenses,
                        size,
                        created_by,
                        repository: None,
                        build_info: None,
                    };
                    blob_infos.push(blob_info);

                    match &component.data {
                        Some(datas) => {
                            for data in datas {
                                match &data.contents {
                                    Some(content) => {}
                                    None => {}
                                }
                            }
                        }
                        None => {}
                    }

                    match &component.group {
                        Some(group) => {
                            println!("group {:?}", group);
                            println!("name {:?}", component.name);
                            match &component.version {
                                Some(version) => {
                                    println!("version {:?}", version);
                                }
                                None => {}
                            }
                        }
                        None => {}
                    }

                    match &component.purl {
                        Some(purl) => {
                            println!("PURL {:?}", purl);
                        }
                        None => {}
                    }

                    match &component.cpe {
                        Some(cpe) => {
                            println!("CPE {:?}", cpe);
                        }
                        None => {}
                    }

                    match &component.swid {
                        Some(swid) => {
                            println!("swid {:?}", swid);
                        }
                        None => {}
                    }

                    //component.cpe
                    //component.swid

                    match &component.hashes {
                        Some(hashes) => {
                            for hash in hashes {
                                println!("hash.content {:?}", hash.content);
                                //HashAlg::MD5 == hash.alg

                                match hash.alg {
                                    crate::model::HashAlg::Md5 => {
                                        println!("hash.alg: Md5");
                                        //return Err((&"booking-fromtime-eq-totime", None))
                                    }
                                    crate::model::HashAlg::Sha1 => println!("hash.alg: Sha1"),
                                    crate::model::HashAlg::Sha256 => println!("hash.alg: Sha256"),
                                    crate::model::HashAlg::Sha384 => println!("hash.alg: Sha384"),
                                    crate::model::HashAlg::Sha512 => println!("hash.alg: Sha512"),
                                    crate::model::HashAlg::Sha3256 => println!("hash.alg: Sha3256"),
                                    crate::model::HashAlg::Sha3384 => println!("hash.alg: Sha3384"),
                                    crate::model::HashAlg::Sha3512 => println!("hash.alg: Sha3512"),
                                    crate::model::HashAlg::Blake2B256 => {
                                        println!("hash.alg: Blake2B256")
                                    }
                                    crate::model::HashAlg::Blake2B384 => {
                                        println!("hash.alg: Blake2B384")
                                    }
                                    crate::model::HashAlg::Blake2B512 => {
                                        println!("hash.alg: Blake2B512")
                                    }
                                    crate::model::HashAlg::Blake3 => println!("hash.alg: Blake3"),
                                };
                            }
                        }
                        None => {}
                    }
                }
            }
            None => {}
        }

        Ok(blob_infos)
    }
}

impl crate::client::trivy::Vulnerability {
    /**
     * Convert a Trivy vulnerability scan result into a CycloneDX vulnerability (VDR, VEX).
     * TODO it remains fields to fill.
     * https://cyclonedx.org/use-cases/security/
     */
    pub fn to_cdx_vulnerability(&self) -> Result<crate::model::Vulnerability, ErrorMsg> {
        let mut cwe_ids: Vec<crate::model::Cwe> = vec![];

        for cwe_id in &self.cwe_ids {
            match cwe_id.to_string().parse::<i64>() {
                Ok(cwe_int) => cwe_ids.push(cwe_int),
                Err(_e) => {}
            }
        }

        let advisories: Option<Vec<crate::model::Advisory>> = None;

        //let json_string = format!(r#""{}""#, self.pkg_name); // Wrap the string in quotes for valid JSON
        //let json_value: Value = from_str(&json_string)?;

        //let v = json!("a string");
        let affects: Option<Vec<crate::model::VulnerabilityItemAffects>> =
            Some(vec![crate::model::VulnerabilityItemAffects {
                //ref_: serde_json::Value::String(serde_json::from_str(&self.pkg_name.to_string())?),
                ref_: json!(&self.pkg_name.to_string()),
                versions: Some(vec![
                    crate::model::VulnerabilityItemAffectsItemVersions::Variant0(json!(
                        &self.installed_version.to_string()
                    )),
                ]),
                /*
                versions: Some(vec![
                    crate::model::VulnerabilityItemAffectsItemVersions::Variant0(
                        serde_json::Value::String(serde_json::from_str(
                            &self.installed_version.to_string(),
                        )?),
                    ),
                ]),
                 */
            }]);
        let analysis: Option<crate::model::VulnerabilityAnalysis> =
            Some(crate::model::VulnerabilityAnalysis {
                detail: None,
                first_issued: match self.published_date {
                    Some(published_date) => Some(published_date.to_string()),
                    None => None,
                },
                justification: None,
                last_updated: match self.last_modified_date {
                    Some(last_modified_date) => Some(last_modified_date.to_string()),
                    None => None,
                },
                response: None,
                state: None,
            });
        let bom_ref: Option<crate::model::RefType> = match &self.pkg_identifier {
            Some(pkg_identifier) => Some(pkg_identifier.bom_ref.clone()),
            None => None,
        };
        let created: Option<String> = None;
        let credits: Option<crate::model::VulnerabilityCredits> = None;
        let cwes: Option<Vec<crate::model::Cwe>> = Some(cwe_ids);
        let description: Option<String> = Some(self.title.to_string());
        let detail: Option<String> = Some(self.description.to_string());
        let id: Option<String> = Some(self.vulnerability_id.clone());
        let proof_of_concept: Option<crate::model::VulnerabilityProofOfConcept> = None;
        let properties: Option<Vec<crate::model::Property>> = None;
        let published: Option<String> = None;
        let ratings: Option<Vec<crate::model::Rating>> = Some(vec![crate::model::Rating {
            justification: None,
            method: None,
            score: None,
            severity: None, //Some(crate::model::Severity::Low),
            source: Some(crate::model::VulnerabilitySource {
                name: Some(self.severity_source.clone()),
                url: None,
            }),
            vector: None,
        }]);
        let recommendation: Option<String> = None;
        let references: Option<Vec<crate::model::VulnerabilityItemReferences>> = None;
        let rejected: Option<String> = None;
        let source: Option<crate::model::VulnerabilitySource> =
            Some(crate::model::VulnerabilitySource {
                name: Some(String::from("Trivy")),
                url: Some(self.primary_url.clone()),
            });
        let tools: Option<crate::model::VulnerabilityTools> = None;
        let updated: Option<String> = None;
        let workaround: Option<String> = None;

        let vulnerability: crate::model::Vulnerability = crate::model::Vulnerability {
            advisories,
            affects,
            analysis,
            bom_ref,
            created,
            credits,
            cwes,
            description,
            detail,
            id,
            proof_of_concept,
            properties,
            published,
            ratings,
            recommendation,
            references,
            rejected,
            source,
            tools,
            updated,
            workaround,
        };
        Ok(vulnerability)
    }
}
