


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
