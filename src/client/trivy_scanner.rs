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
use sha2::{Digest, Sha256};
use tower::{Service, ServiceExt};
use trivy::{
    ArtifactInfo, BlobInfo, CustomResource, DeleteBlobsRequest, DetectedLicense,
    DetectedMisconfiguration, LicenseCategory, Licenses, MissingBlobsRequest, MissingBlobsResponse,
    Os, Package, PutArtifactRequest, PutBlobRequest, PutResponse, Result, ScanOptions, ScanRequest,
    ScanResponse, SecretFinding, cache_client,
};

use crate::{
    client::{get_hyper_client, get_hyper_client_unsecure, trivy::{cache_server::Cache, scanner_client::ScannerClient, scanner_server::Scanner}},
    error::ErrorMsg,
    model::{CdxBom, HashAlg, LicenseChoiceUrl, TRIVY_PROXY_PK},
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
pub async fn scan_cdx(cdx: &CdxBom, lang: &String) -> core::result::Result<(), ErrorMsg> {
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

    scan_blob_infos(&blob_infos).await?;
    Ok(())
}

pub async fn scan_blob_infos(blob_infos: &Vec<BlobInfo>) -> core::result::Result<(), ErrorMsg> {
    let results: Vec<Result> = vec![];

    for blob_info in blob_infos {
        //let diff_id = rand::distr::SampleString::sample_string(&rand::distr::Alphanumeric, &mut rand::rng(), 16);
        //TODO diff_id sha256

        let random_string = rand::distr::SampleString::sample_string(&rand::distr::Alphanumeric, &mut rand::rng(), 16);
        let mut diff_id_hex = Sha256::new();
        diff_id_hex.update(random_string);
        let diff_id: String = format!("sha256:{:X}", diff_id_hex.finalize());

        //String::from("sha256:") + &diff_id, //+random sha256,
        let put_blob_http: PutBlobRequest = PutBlobRequest {
            blob_info: Some(blob_info.clone()),
            diff_id: blob_info.diff_id.clone()// diff_id.clone()
        };

        //let str = String::from_utf8(put_blob_http.encode_to_vec())?;
        //println!("put_blob_http bytes u8 {:?} ", str);

        // Serialize the message to a byte array using Prost
        let mut buf = Vec::new();
        prost::Message::encode(&put_blob_http, &mut buf)?;


        //https://github.com/twitchtv/twirp?tab=readme-ov-file
        let prod = crate::model::PROD.as_str();
        let request = hyper::Request::builder()
            .method("POST")
            //.uri(String::from("https://127.0.0.1:10001/twirp/trivy.cache.v1.Cache/PutBlob"))
            .uri(String::from("http://127.0.0.1:10000/twirp/trivy.cache.v1.Cache/PutBlob"))
            .header("Content-Type", "application/protobuf")
            .header("Host", "127.0.0.1")
            .version(hyper::Version::HTTP_2)
            .body(axum::body::Body::from(buf))?;
            //.body(axum::body::Body::from(serde_json::to_vec(&buf)?))?;
            //.body(axum::body::Body::empty())?;


        /*let host = url.host().expect("uri has no host");
        let port = url.port_u16().unwrap_or(80);
        let addr = format!("{}:{}", host, port);
        */
        let url = String::from("http://127.0.0.1:10000");
        let stream = tokio::net::TcpStream::connect(String::from("127.0.0.1:10000")).await?;
        let io = hyper_util::rt::TokioIo::new(stream);
    
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                println!("Connection failed: {:?}", err);
            }
        });
    
        let mut response = sender.send_request(request).await?;
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
            let body_bytes = http_body_util::BodyExt::collect(response.into_body()).await?.to_bytes();
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
        let scan_blob: ScanRequest = ScanRequest { 
            target: blob_info.diff_id.clone().clone(), 
            artifact_id: blob_info.diff_id.clone().clone(), 
            blob_ids: vec![blob_info.diff_id.clone().clone().clone()], 

            options: Some(ScanOptions { pkg_types: vec!["library".to_string(), "os".to_string()], scanners: vec!["vuln".to_string()], license_categories: HashMap::new(), include_dev_deps: false, 
            pkg_relationships: vec!["unknown".to_string(),"root".to_string(),"workspace".to_string(),"direct".to_string(),"indirect".to_string()] }) 
        };

        let mut buf = Vec::new();
        prost::Message::encode(&scan_blob, &mut buf)?;
        let request = hyper::Request::builder()
            .method("POST")
            .uri(String::from("http://127.0.0.1:10000/twirp/trivy.scanner.v1.Scanner/Scan"))
            .header("Content-Type", "application/protobuf")
            .header("Host", "127.0.0.1")
            .version(hyper::Version::HTTP_2)
            .body(axum::body::Body::from(buf))?;

        let mut response = sender.send_request(request).await?;

        if response.status() != hyper::StatusCode::OK {
            println!("Scan response: {} ", response.status());
            //let body_bytes = axum::body::to_bytes(response.into_body(), MAX_BODY_SIZE).await?;
            let body_bytes = http_body_util::BodyExt::collect(response.into_body()).await?.to_bytes();
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
            let body_bytes = http_body_util::BodyExt::collect(response.into_body()).await?.to_bytes();
            //println!("Body bytes {:X} ", body_bytes);
            //let mut buf: &[u8] = &body_bytes.to_vec();
            //println!("Body bytes u8 {:X} ", buf);
            //let scan_response: ScanResponse = prost::Message::decode(buf)?;
            let scan_response: ScanResponse = prost::Message::decode(&body_bytes[..])?;
            

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
                    println!("  package digest: {}", package.digest);
                }
                for custom_resource in &result.custom_resources {
                    println!("  custom_resource file_path: {}", custom_resource.file_path);
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

    Ok(())
}

pub struct MyTrivyImpl {}
/*
#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        println!("Got a request: {:?}", request);

        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };

        Ok(Response::new(reply))
    }
}
*/

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
        dangerous_config.set_certificate_verifier(std::sync::Arc::new(crate::client::NoCertificateVerification {}));

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

impl CdxBom {
    pub fn to_trivy_blob_info(
        &self,
    ) -> std::result::Result<Vec<BlobInfo>, (&&str, Option<HashMap<String, String>>)> {
        let mut blob_infos: Vec<BlobInfo> = vec![];

        let mut i: i32 = 0;
        //packageInfo, application, os, componentByPUrl
        match &self.components {
            Some(components) => {
                for component in components {

                    
                    println!("component.type_: {:?}", component.type_);
                    i = i+1;
                    let mut package_infos: Vec<Package> = vec![];
                    let mut os: Option<Os> = None;

                    let digest: String = match &component.hashes {
                        Some(hashes) => match hashes.iter().find(|h| h.alg == HashAlg::Sha256) {
                            Some(sha_256) => String::from("SHA256:") + &sha_256.content,
                            None => {
                                match hashes.iter().find(|h| h.alg == HashAlg::Sha1) {
                                    Some(sha_1) => String::from("SHA1:") + &sha_1.content,
                                    None => {
                                        //let mut map: HashMap<String, String> = HashMap::new();
                                        //map.insert("component_name".to_string(), component.name.clone());
                                        //return Err((&"sha256-of-component-not-provided", Some(map)));
                                        String::from("")
                                    }
                                }
                            }
                        },
                        None => {
                            //let mut map: HashMap<String, String> = HashMap::new();
                            //map.insert("component_name".to_string(), component.name.clone());
                            //return Err((&"sha256-of-component-not-provided", Some(map)));
                            String::from("")
                        }
                    };
                    match &component.properties {
                        Some(properties) => {
                            for property in properties {
                                //println!("property name: {:?}", property.name);
                                match &property.value {
                                    Some(value) => {
                                        //println!("property value: {:?}", value);
                                    },
                                    None => {},
                                }
                            }
                        },
                        None => {

                        },
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

                                let name = match package_type == "cocoa" || package_type == "maven" || package_type == "gradle" || package_type == "bitnami"  {
                                    true => packageurl.name().to_string(),
                                    false => {
                                        let name = match &component.group {
                                            Some(group) => {
                                                group.to_string() + &String::from("/") + &component.name.to_string()
                                            },
                                            None => component.name.to_string(),
                                        };
                                        name
                                    },
                                };

                                let arch = match packageurl.qualifiers().get("arch") {
                                    Some(architecture) => architecture.to_string(),
                                    None => String::from("x86_64"),
                                };

                                let epoch = match packageurl.qualifiers().get("epoch") {
                                    Some(epoch) => {
                                        match epoch.to_string().parse::<i32>() {
                                            Ok(val) => val,
                                            Err(_e) => 2,
                                        }
                                    }
                                    None => 1,
                                };

                                let distro = match packageurl.qualifiers().get("distro") {
                                    Some(distro) => distro.to_string(),
                                    None => String::from(""),
                                };
    
                                let version = match &packageurl.version() {
                                    Some(version) => version.to_string(),
                                    None => String::from(""),
                                };
    
                                let package: Package = Package {
                                    id: package_type.to_string() + &packageurl.name().to_string() + &version.clone(), //i.to_string(),
                                    name: name,//packageurl.name().to_string(),
                                    //name: String::from(""),
                                    version: version.clone(),
                                    release: String::from("1"),
                                    epoch: epoch,
                                    arch: arch,
                                    //src_name: packageurl.name().to_string(),
                                    //src_version: version,
                                    src_name: String::from("src"),
                                    src_version: String::from("1.2.3"),
                                    src_release: String::from("1"),
                                    src_epoch: epoch,
                                    licenses: vec![],
                                    file_path: String::from(""),
                                    digest: digest.clone(),
                                    dev: false,
                                    indirect: true,
                                };
                                package_infos.push(package);
                            }
                        },
                        None => {
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
                                false => {},
                            };
                        },
                    }


                    let applications: Vec<CustomResource> = vec![];
                    let opaque_dirs: Vec<String> = vec![];
                    let whiteout_files: Vec<String> = vec![];
                    let misconfigurations: Vec<DetectedMisconfiguration> = vec![];





                    //let random_string = rand::distr::SampleString::sample_string(&rand::distr::Alphanumeric, &mut rand::rng(), 16);
                    //let diff_id: String = String::from("sha256:...");
                    //TODO it should be sha256:...
                    //let diff_id_hex = sha2::Sha256::digest(random_string.as_bytes());
                    //let mut diff_id_hex = Sha256::new();
                    //diff_id_hex.update(random_string);
                    //let diff_id: String = format!("{:X}", diff_id_hex.finalize());

                    let random_string = rand::distr::SampleString::sample_string(&rand::distr::Alphanumeric, &mut rand::rng(), 16);
                    let mut diff_id_hex = Sha256::new();
                    diff_id_hex.update(random_string);
                    let diff_id: String = format!("sha256:{:X}", diff_id_hex.finalize());

                    let custom_resources: Vec<CustomResource> = vec![];
                    let secrets: Vec<SecretFinding> = vec![];

                    let licenses: Vec<DetectedLicense> = match &component.licenses {
                        Some(licenses) => {
                            match licenses {
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

                    let blob_info: BlobInfo = BlobInfo {
                        schema_version: 2,
                        os,
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

                    /*
                    let mut package_info: Package = Package {
                        id: (),
                        name: (),
                        version: (),
                        release: (),
                        epoch: (),
                        arch: (),
                        src_name: (),
                        src_version: (),
                        src_release: (),
                        src_epoch: (),
                        licenses: (),
                        file_path: (),
                        digest: (),
                        dev: (),
                        indirect: ()
                    };
                    */

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

