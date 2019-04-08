#!/bin/bash

set -x
. ./config

sed -e "s|@MODULE_PATH@|${REAL_PKCS11_MODULE}|g" -e "s|@ENGINE_PATH@|$ENGINE|g" <"./engines.cnf.in" >"$DATADIR/engines.cnf"

cmdline="rsautl \
-sign \
-engine pkcs11 \
-keyform engine \
-inkey $PRIVATE_KEY2 \
-in testdata \
-out $DATADIR/testdata.sign"

echo "set args $cmdline" > .gdbinit
export OPENSSL_CONF=$DATADIR/engines.cnf

#LD_DEBUG=all \

OPENSSL_CONF=$DATADIR/engines.cnf \
$OPENSSL \
	$cmdline
