#!/bin/bash

export https_proxy=
export http_proxy=
set -x
current_dir=$(dirname "$(readlink -f "$0")")
. ${current_dir}/../config

PRIVATE_KEY="pkcs11:token=$TOKENNAME;id=$KEYID_AES;object=$AES_LABEL;type=private;pin-value=$PIN"
sed -e "s|@MODULE_PATH@|${REAL_PKCS11_MODULE}|g" -e "s|@ENGINE_PATH@|$ENGINE|g" <". ${CURRENT_DIR}/engines.cnf.in" >"$DATADIR/engines.cnf"

echo "set args $cmdline" > .gdbinit
export INSTALLDIR=$INSTALLDIR
OPENSSL_CONF=$DATADIR/engines.cnf LD_LIBRARY_PATH=${INSTALLDIR}/lib ${current_dir}/aes_encrypt_decrypt $PRIVATE_KEY
