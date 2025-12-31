fn main() -> Result<(), Box<dyn std::error::Error>> {

    tonic_prost_build::compile_protos("proto/trivy.proto")?;
    tonic_prost_build::compile_protos("proto/protobom.proto")?;

    Ok(())
}
