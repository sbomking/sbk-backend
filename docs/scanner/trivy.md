

#Health endpoint

http://127.0.0.1:10000/healthz



# Download image
docker pull fullstorydev/grpcurl:latest
# Run the tool
docker run fullstorydev/grpcurl api.grpc.me:443 list
podman run fullstorydev/grpcurl -plaintext host.docker.internal:10000 list

grpcurl -H header1:value1 -H header2:value2 -d '{"id": 1234, "tags": ["foo","bar"]}' grpc.server.com:443 my.custom.server.Service/Method

grpcurl -plaintext -import-path ./proto -proto helloworld.proto -d '{"name": "Tonic"}' '[::1]:50051' helloworld.Greeter/SayHello


grpcurl -plaintext 127.0.0.1:10000 list
./grpcurl -plaintext -max-time 10 127.0.0.1:10000 list

Docker

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

Podman

podman play kube trivy.yaml
