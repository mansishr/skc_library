#!/bin/sh

# Utility to recreate test certificates

OPENSSL=openssl
OPENSSL_CONF=./ca.cnf
export OPENSSL_CONF

ROOTCERT=rootcert.pem
CERT=test-rsa-cert.pem

# Root CA: create certificate directly
CN="Test RSA Root" $OPENSSL req -config ca.cnf -x509 -nodes \
	-keyout $ROOTCERT -out $ROOTCERT -newkey rsa:2048 -days 3650

# EE RSA certificates: create request first
CN="Test EE RSA #1" $OPENSSL req -config ca.cnf -nodes \
	-keyout $CERT -out req.pem -newkey rsa:2048

# Sign request: end entity extensions
$OPENSSL x509 -req -in req.pem -CA $ROOTCERT -days 3600 \
	-extfile ca.cnf -extensions usr_cert -CAcreateserial >>$CERT 

# Remove temp files.
rm -f req.pem *.srl
