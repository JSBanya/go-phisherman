#!/bin/bash
if [ ! -f certs/$1.crt ]; then
	SUBJ="/C=US/ST=New Jersey/O=PhisherMan/CN=$1"
	export SAN="DNS:$1"
	openssl req -new -nodes -newkey rsa:2048 -keyout certs/$1.key -out certs/$1.csr -subj "$SUBJ" -config openssl.cnf -reqexts SAN
	openssl x509 -req -in certs/$1.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out certs/$1.crt -extensions SAN -extfile openssl_san.cnf
fi
