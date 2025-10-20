pub mod trivy {
    tonic::include_proto!("trivy.rpc.v1");
}

use core::panic;
use std::collections::HashMap;

use trivy::{cache_client, ArtifactInfo, BlobInfo, CustomResource, DeleteBlobsRequest, DetectedLicense, DetectedMisconfiguration, LicenseCategory, Licenses, MissingBlobsRequest, MissingBlobsResponse, Os, Package, PutArtifactRequest, PutBlobRequest, PutResponse, Result, ScanOptions, ScanRequest, ScanResponse, SecretFinding};
use rustls_pki_types::pem::PemObject;

use crate::{client::trivy::{cache_server::Cache, scanner_server::Scanner}, error::ErrorMsg, model::{CdxBom, HashAlg, LicenseChoiceUrl, TRIVY_PROXY_PK}};
//use api::{publisher_client::PublisherClient, ListTopicsRequest};

/**
 * Client integration with a trivy server.
 */
pub async fn scan_cdx(cdx: &CdxBom, lang: &String) -> core::result::Result<(), ErrorMsg> {

    let blob_infos: Vec<BlobInfo> = match cdx.to_trivy_blob_info() {
        Ok(blobs) => blobs,
        Err((validation_error, arg_map_opt)) => {
            return Err(ErrorMsg{title: crate::util::get_message(lang, validation_error, &arg_map_opt), status: hyper::StatusCode::CONFLICT.as_u16(), _type: None, detail: None, instance: None, code: None, errors: vec![] })
        }
    };

    

    scan_blob_infos(&blob_infos).await?;
    Ok(())
}


pub async fn scan_blob_infos(blob_infos: &Vec<BlobInfo>) -> core::result::Result<(), ErrorMsg> {

    let results: Vec<Result> = vec![];

    

    for blob_info in blob_infos {
        let put_blob: PutBlobRequest = PutBlobRequest {
            blob_info: Some(blob_info.clone()),
            diff_id: String::from("sha256:") //+random sha256, 
        };

        let put_blob_request = tonic::Request::new(put_blob);

        let my_trivy = MyTrivyImpl {

        };

        match my_trivy.put_blob(put_blob_request).await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("calling put_blob failed: {:?}", e);
                println!("calling put_blob failed {:?}", e);
                panic!("calling put_blob failed: {:?}", e)
            }
        };

        //my_trivy.scan_blob_infos(blob_infos).await?;

        //let blob_scan_result = Scanner::scan(&'life0 self, request)
        //results.append(blob_scan_result);
    }

    Ok(())
}


pub struct MyTrivyImpl {

}
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
        
        let endpoint = "https://[::1]:10001";

        match tonic::transport::Channel::from_static(endpoint).connect().await {
            Ok(channel) => {
                println!("✅ Successfully connected to {}", &endpoint);
                // You can now use `channel` to create your client
            }
            Err(e) => {
                println!("❌ Failed to connect: {}", e);
            }
        };


        match tonic::transport::Endpoint::from_static(endpoint)
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(10))
                .http2_keep_alive_interval(std::time::Duration::from_secs(30))
                .keep_alive_while_idle(true).connect().await {
            Ok(channel) => {
                println!("✅ HTTP2 Successfully connected to {}", &endpoint);
                // You can now use `channel` to create your client
            }
            Err(e) => {
                println!("❌ HTTP2 Failed to connect: {}", e);
            }
        };

        match tonic::transport::Channel::from_static(endpoint).connect().await {
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

         let certs = rustls_pki_types::CertificateDer::from_pem_slice(&String::from(TRIVY_PROXY_PK.as_str()).as_bytes()).expect("Failed to parse PEM certificate");
         let mut roots = rustls::RootCertStore::empty();
         match roots.add(certs) {
             Ok(_) => {},
             Err(_) => panic!("OLOLOL ERROR"),
         }
         let tls = rustls::ClientConfig::builder()
             .with_root_certificates(roots)
             .with_no_client_auth();
     
     
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
             .service(http);
     
         let hyper_client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector);

         let uri = hyper::Uri::from_static("https://127.0.0.1:10001");
         let mut cc = cache_client::CacheClient::with_origin(hyper_client, uri);


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
         let response = cc.put_blob(request).await?;
    
         println!("RESPONSE={:?}", response);

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
        let mut client = match cache_client::CacheClient::connect(endpoint).await
        {
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
        println!("Checking missing blobs for artifact_id: {}", req.artifact_id);

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

	pub fn to_trivy_blob_info(&self) -> std::result::Result<Vec<BlobInfo>, (&&str, Option<HashMap<String,String>>)> {
        
		let mut blob_infos: Vec<BlobInfo> = vec![];

        //packageInfo, application, os, componentByPUrl
        match &self.components {
            Some(components) => {
                for component in components {


                    let os: Option<Os> = match component.type_ == "operating-system" {
                        true => {
                            let os: Os = Os {
                                family: todo!(),
                                name: todo!(),
                                eosl: todo!(),
                                extended: todo!(),
                            };
                            Some(os)
                        },
                        false => None,
                    };

                    let package_infos: Vec<Package> = vec![];
                    let applications: Vec<CustomResource> = vec![];
                    let opaque_dirs: Vec<String> = vec![];
                    let whiteout_files: Vec<String> = vec![];
                    let misconfigurations: Vec<DetectedMisconfiguration> = vec![];

                    let digest: String = match &component.hashes {
                        Some(hashes) => {
                            match hashes.iter().find(|h| h.alg == HashAlg::Sha256) {
                                Some(sha_256) => sha_256.content.clone(),
                                None => {
                                    let mut map: HashMap<String, String> = HashMap::new();
                                    map.insert("component_name".to_string(), component.name.clone());
                                    return Err((&"sha256-of-component-not-provided", Some(map)))
                                },
                            }
                        },
                        None => {
                            let mut map: HashMap<String, String> = HashMap::new();
                            map.insert("component_name".to_string(), component.name.clone());
                            return Err((&"sha256-of-component-not-provided", Some(map)))
                        }
                    };

                    let diff_id: String = String::from("diff_id...");
                    let custom_resources: Vec<CustomResource> = vec![];
                    let secrets: Vec<SecretFinding> = vec![];
                    
                    let licenses: Vec<DetectedLicense> = match &component.licenses {
                        Some(licenses) => {
                            match licenses {
                                LicenseChoiceUrl::Variant0(license_choice_url_variant0_item_urls) => {
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
                                },
                                LicenseChoiceUrl::Variant1(license_choice_url_variant1_item_licenses) => {
                                    vec![]
                                },
                            }
                        },
                        None => vec![],
                    };
                    let size: i64 = 7;
                    let created_by: String = String::from("created_by");

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
                        created_by
                    };
                    blob_infos.push(blob_info);

                    match &component.data {
                        Some(datas) => {
                            for data in datas {
                                match &data.contents {
                                    Some(content) => {},
                                    None => {},
                                }
                            }
                        },
                        None => {},
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
                                },
                                None => {}
                            }
                        },
                        None => {}
                    }
    
                    match &component.purl {
                        Some(purl) => {
                            println!("PURL {:?}", purl);
                        },
                        None => {},
                    }
    
                    match &component.cpe {
                        Some(cpe) => {
                            println!("CPE {:?}", cpe);
                        },
                        None => {},
                    }
    
                    match &component.swid {
                        Some(swid) => {
                            println!("swid {:?}", swid);
                        },
                        None => {},
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
                                    },
                                    crate::model::HashAlg::Sha1 => println!("hash.alg: Sha1"),
                                    crate::model::HashAlg::Sha256 => println!("hash.alg: Sha256"),
                                    crate::model::HashAlg::Sha384 => println!("hash.alg: Sha384"),
                                    crate::model::HashAlg::Sha512 => println!("hash.alg: Sha512"),
                                    crate::model::HashAlg::Sha3256 => println!("hash.alg: Sha3256"),
                                    crate::model::HashAlg::Sha3384 => println!("hash.alg: Sha3384"),
                                    crate::model::HashAlg::Sha3512 => println!("hash.alg: Sha3512"),
                                    crate::model::HashAlg::Blake2B256 => println!("hash.alg: Blake2B256"),
                                    crate::model::HashAlg::Blake2B384 => println!("hash.alg: Blake2B384"),
                                    crate::model::HashAlg::Blake2B512 => println!("hash.alg: Blake2B512"),
                                    crate::model::HashAlg::Blake3 => println!("hash.alg: Blake3"),
                                };
    
                            }
                        },
                        None => {},
                    }                
                }
            },
            None => {}
        }


		Ok(blob_infos)
	}
}