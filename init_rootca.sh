#!/bin/bash
if [ -f rootCA.crt ]; then
	echo "Root CA certificate has already been generated! Aborting."
	exit
fi
(echo "US"; echo "New Jersey"; echo "Hoboken"; echo "PhisherMan"; echo "Proxy Server"; echo "PhisherMan Root CA"; echo) | \
openssl req -x509 -new -nodes -newkey rsa:2048 -keyout rootCA.key -out rootCA.crt 2> /dev/null && \
echo "Root CA certificate has been generated" && \
echo "Please install rootCA.crt in your browser before using PhisherMan"
