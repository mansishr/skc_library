#!/bin/bash

unset http_proxy
unset https_proxy

set -x
current_dir=$(dirname "$(readlink -f "$0")")
. ${current_dir}/../config

PRIVATE_KEY="pkcs11:token=$TOKENNAME;id=$KEYID_RSA;object=$RSA_LABEL;type=private;pin-value=$PIN"
sed -e "s|@MODULE_PATH@|${REAL_PKCS11_MODULE}|g" -e "s|@ENGINE_PATH@|$ENGINE|g" <"${CURRENT_DIR}/engines.cnf.in" >"$DATADIR/engines.cnf"

cmdline="rsautl \
-verify \
-engine pkcs11 \
-keyform engine \
-inkey $PRIVATE_KEY \
-out $DATADIR/testdata.verify \
-in $DATADIR/testdata.sign"

echo "set args $cmdline" > .gdbinit
export OPENSSL_CONF=$DATADIR/engines.cnf

OPENSSL_CONF=$DATADIR/engines.cnf \
$OPENSSL \
	$cmdline
