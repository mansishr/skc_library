#!/bin/bash

set -x

current_dir=$(dirname "$(readlink -f "$0")")
. ${current_dir}/config

TOKEN_CNT=`pkcs11-tool --module $MODULE -L | grep 'token label' | grep -c "\<$TOKENNAME\>"`

if [ $TOKEN_CNT -eq 1 ]; then

	if [ "x$SGX" = "x" ]; then
		TOKEN_SLOT=`pkcs11-tool --module $MODULE -L |  tr '\n' '@' | sed -e "s/.*SoftHSM slot \(.*\)@\s\+token label\s\+: $TOKENNAME@.*/\1/"`
	elif [ -d "$TOOLKIT_INSTALLDIR" ] && [ "x$SGX" == "x1" ]; then
 		TOKEN_SLOT=`pkcs11-tool --module $MODULE -L |  tr '\n' '@' | sed -e "s/.*Crypto API Toolkit Slot ID:\(.*\)@\s\+token label\s\+: $TOKENNAME@.*/\1/"`

	fi

	echo "Token:$TOKENNAME found in module:$MODULE, below are objects in the token"
	pkcs11-tool --module $MODULE --list-objects --login --pin $PIN --slot $TOKEN_SLOT
else
	echo "Token:$TOKENNAME not found in module:$MODULE"
fi
