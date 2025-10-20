openssl req -x509 -batch -subj "/C=BE/ST=Some-State/CN=127.0.0.1/O=Sbomking-self-signed" -nodes -newkey rsa:2048 -keyout ./localhost-selfsigned.key -out ./localhost-selfsigned.crt -days 3650
openssl dhparam -out dhparam-localhost.pem 2048
