pub mod trivy {
    tonic::include_proto!("trivy.rpc.v1");
}

use trivy::{ArtifactInfo, BlobInfo, CustomResource, DeleteBlobsRequest, DetectedLicense, DetectedMisconfiguration, LicenseCategory, Licenses, MissingBlobsRequest, MissingBlobsResponse, Os, Package, PutArtifactRequest, PutBlobRequest, PutResponse, Result, ScanOptions, ScanRequest, ScanResponse, SecretFinding};
//use api::{publisher_client::PublisherClient, ListTopicsRequest};
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