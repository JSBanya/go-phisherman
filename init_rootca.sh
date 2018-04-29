#!/bin/bash
if [ -f rootCA.crt ]; then
	echo "Root CA certificate has already been generated! Aborting."
	exit
fi
SUBJ="/C=US/ST=New Jersey/L=Hoboken/O=PhisherMan/OU=Proxy Server/CN=PhisherMan Root CA"
openssl req -x509 -new -nodes -newkey rsa:2048 -keyout rootCA.key -out rootCA.crt -subj "$SUBJ" && \
echo "Root CA certificate has been generated" && \
echo "Please install rootCA.crt in your browser before using PhisherMan"
