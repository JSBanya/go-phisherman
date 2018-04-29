#!/bin/bash
if [ ! -f certs/$1.crt ]; then
	(echo "US"; echo "New Jersey"; echo "Hoboken"; echo; echo; echo $1; echo; echo; echo) | openssl req -new -nodes -newkey rsa:2048 -keyout certs/$1.key -out certs/$1.csr
	openssl x509 -req -in certs/$1.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out certs/$1.crt
fi
