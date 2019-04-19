#!/bin/sh
set -x

# Utility to recreate test certificates
OPENSSL=openssl

CA_CONF_PATH=__PREFIX__/store/testserver/ca.cnf
OPENSSL_CONF=${CA_CONF_PATH}
export OPENSSL_CONF

CERT_DIR=__PREFIX__/store/testserver/ssl

rm -rf ${CERT_DIR}
mkdir -p ${CERT_DIR}/{CA,client,server}

CA_CERT_DIR=${CERT_DIR}/CA
SERVER_CERT_DIR=${CERT_DIR}/server
CLIENT_CERT_DIR=${CERT_DIR}/client

CA_ROOT_CERT=${CA_CERT_DIR}/root_certificate.pem
CLIENT_ROOT_CERT=${CA_CERT_DIR}/client_root_certificate.pem
SERVER_CERT=${SERVER_CERT_DIR}/server_certificate.pem
CLIENT_CERT5=${CLIENT_CERT_DIR}/certificate.pem
CLIENT_KEY=${CLIENT_CERT_DIR}/certificate_key.pem
DHPARAM=${CLIENT_CERT_DIR}/dhparam.pem 

# Root CA: create certificate directly
CN="Test RSA Root" $OPENSSL req -config ${CA_CONF_PATH} -x509 -nodes \
	-keyout ${CA_ROOT_CERT} -out ${CA_ROOT_CERT} -newkey rsa:2048 -days 3650

ln -s ${CA_ROOT_CERT} ${CA_CERT_DIR}/$(eval ${OPENSSL} x509 -hash -in ${CA_ROOT_CERT} -noout ).0

# EE RSA certificates: create request first
CN="testserver" $OPENSSL req -config ${CA_CONF_PATH} -nodes \
	-keyout ${SERVER_CERT} -out ${SERVER_CERT_DIR}/req.pem -newkey rsa:2048

# Sign request: end entity extensions
$OPENSSL x509 -req -in ${SERVER_CERT_DIR}/req.pem -CA ${CA_ROOT_CERT} -days 3600 \
	-extfile ${CA_CONF_PATH} -extensions usr_cert -CAcreateserial >> ${SERVER_CERT} 


$OPENSSL dhparam 768 -out ${DHPARAM} -outform PEM


CN="CLIENT Root" $OPENSSL req -config ${CA_CONF_PATH} -x509 -nodes \
	-keyout ${CLIENT_ROOT_CERT} -out ${CLIENT_ROOT_CERT} -newkey rsa:2048 -days 3650

ln -s ${CLIENT_ROOT_CERT} ${CA_CERT_DIR}/$(eval ${OPENSSL} x509 -hash -in ${CLIENT_ROOT_CERT} -noout ).0


$OPENSSL genrsa -out ${CLIENT_KEY} 2048

CN="localhost" $OPENSSL req -new -nodes \
	-key ${CLIENT_KEY} -out ${CLIENT_CERT_DIR}/req.pem &> /dev/null

$OPENSSL x509 -req -in ${CLIENT_CERT_DIR}/req.pem -CA ${CLIENT_ROOT_CERT} -days 3600 \
	-extfile ${CA_CONF_PATH} -extensions usr_cert -CAcreateserial >> ${CLIENT_CERT5} 


#source __PREFIX__/etc/credential_agent.ini
#$SOFTHSMDIR/bin/softhsm2-util --delete-token --slot 2 --token $TOKENNAME
#$SOFTHSMDIR/bin/softhsm2-util --init-token  --label $TOKENNAME --slot 0 --pin $PIN --so-pin $PIN

#pkcs11-tool --module $REAL_PKCS11_MODULE --login --pin 1234 \
   #--id $KEYID --token $TOKENNAME --keypairgen --key-type rsa:2048 --label $KEYLABEL --usage-sign &> /dev/null

#OPENSSL_CONF=__PREFIX__/etc/engines.cnf \
	#$OPENSSL req -nodes -new -engine pkcs11 -keyform engine -key $PRIVATE_KEY -out ${CLIENT_CERT_DIR}/req.pem \
	#-subj '/CN=intel client' &> /dev/null

#$OPENSSL x509 \
		#-req -in ${CLIENT_CERT_DIR}/req.pem -CA ${CLIENT_ROOT_CERT} \
        #-extfile ${CA_CONF_PATH} -extensions usr_cert -CAcreateserial \
		#-in ${CLIENT_CERT_DIR}/req.pem \
        #-req -days 365 -out ${CLIENT_CERT5}

find ${CERT_DIR}
