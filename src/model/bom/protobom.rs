use std::collections::HashMap;

pub mod protobom {
    tonic::include_proto!("protobom.protobom");
}

impl crate::model::bom::protobom::protobom::Document {
    pub fn to_protobom(
        &self,
    ) -> std::result::Result<(), (&&str, Option<HashMap<String, String>>)> {
        
        Ok(())
    }
}

