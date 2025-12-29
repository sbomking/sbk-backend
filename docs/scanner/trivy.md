# Trivy integration

## How to deploy
You can find below two ways to deploy the trivy server.

### Deploy with docker-compose

docker-compose.yml

----
services:
  trivy:
    image: aquasec/trivy:latest
    command:
    - server
    - --listen
    - :10000
    - --token
    - yourAuthToken
    volumes:
    - "trivy-cache:/root/.cache/trivy"
    restart: unless-stopped

volumes:
  trivy-cache: {}
----

### Deploy with Podman
podman play kube trivy.yaml


## Contribute
Prost is used to convert the protobuf definition (.proto) to a Rust struct at compile time.
The protobuf definition are stored in the proto folder.

### Protobuf definition
The original .proto can be found in the trivy git repository. 
The original protos have been reworked to specify optional field.

### How to reverse engineer the client
./trivy sbom centos-7-cyclonedx.json --server http://127.0.0.1:10000 
sudo tcpdump -i any port 10000 -c 100 -w trivy.pcap
Open the pcap with Wireshark.

### Protoc decode
It can help to decode the protobuf bin.

-- Rust code
let mut file = std::fs::OpenOptions::new()
    .create(true)
    .write(true)
    .open("/my_path/sbk-backend/proto/trivy.bin")?;
std::io::Write::write_all(&mut file, &buf)?;

-- Protoc command
protoc --decode=trivy.rpc.v1.PutBlobRequest trivy.proto < trivy.bin