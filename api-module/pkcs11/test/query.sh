#!/bin/bash

set -x
. ./config

DO_SPY=
#DO_SPY=$SPY

if [ "x$SGX" != "x" ]
then
    MODE=SGX
    if [ "x$DO_SPY" == "x1" ]
    then
        export PKCS11SPY=$TOOLKIT_INSTALLDIR/lib/libp11sgx.so
        MODULE=$SPY_MODULE
    else
        MODULE=$TOOLKIT_INSTALLDIR/lib/libp11sgx.so
        export PKCS11SPY=
    fi
else
    MODE=SW
    $SOFTHSM_UTIL --show-slots
    if [ "x$DO_SPY" == "x1" ]
    then
        export PKCS11SPY=$SOFTHSM_LIB
        MODULE=$SPY_MODULE
    else
        MODULE=$SOFTHSM_LIB
        export PKCS11SPY=
    fi
fi

pkcs11-tool --module $MODULE --list-slots
pkcs11-tool --module $MODULE --show-info
pkcs11-tool --module $MODULE --list-token-slots
#pkcs11-tool --module $MODULE --list-mechanisms
pkcs11-tool --module $MODULE --list-objects --label REFERENCE
pkcs11-tool --module $MODULE --list-objects --type secrkey --label REFERENCE
pkcs11-tool --module $MODULE --list-objects --login --pin $PIN
