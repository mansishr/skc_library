set -x
current_dir=$(dirname "$(readlink -f "$0")")
. ${current_dir}/config

TOKEN_CNT=`pkcs11-tool --module ${MODULE} -L | grep 'token label' | grep -c "\<$TOKENNAME\>"`

if [ $TOKEN_CNT -eq 1 ]; then
	if [ "x$SGX" == "x" ] && [ -d $SOFTHSM_TOKEN_DIR ]; then
		TOKEN_SLOT=`pkcs11-tool --module $MODULE -L |  tr '\n' '@' | sed -e "s/.*SoftHSM slot \(.*\)@\s\+token label\s\+: $TOKENNAME@.*/\1/"`
		rm -rf ${SOFTHSM_TOKEN_DIR}/*

	elif [ "x$SGX" == "x1" ]; then
		if [ ! -d "$TOOLKIT_TOKEN_DIR" ]; then
			echo "Please set correct Toolkit Token directory path variable: \$TOOLKIT_TOKEN_DIR in config"
			exit -1 
		fi
		rm -fr  ${TOOLKIT_TOKEN_DIR}/tokens/*
	fi
else
	echo "Nothing to clean: $TOKENNAME not found\n"
fi

rm -fr core*
