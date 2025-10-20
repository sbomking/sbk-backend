FROM nginxinc/nginx-unprivileged:stable-alpine-slim

COPY nginx.conf /etc/nginx/templates/default.conf.template

COPY --chown=nginx:root --chmod=755 certs/localhost-selfsigned.crt /etc/ssl/certs/localhost-selfsigned.crt
COPY --chown=nginx:root --chmod=755 certs/localhost-selfsigned.key /etc/ssl/private/localhost-selfsigned.key
COPY --chown=nginx:root --chmod=755 certs/dhparam-localhost.pem /etc/ssl/certs/dhparam-localhost.pem

USER root
RUN chown nginx:root /usr/share/nginx/html

USER 101
#podman build -t nginx_trivy:0.0.1 .