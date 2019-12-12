#!/bin/bash
#wget https://curl.haxx.se/download/curl-7.64.1.tar.gz
script_dir=$(dirname "$(readlink -f "$0")")
source ${script_dir}/config.ini

if [ -f ${script_dir}/$UTILS_SOURCE ]; then
    source ${script_dir}/$UTILS_SOURCE
else
    echo -e "Utils Script not found Error, Exit." && exit 1
fi

set_log $FLAG_ENABLE "LIBCURL"


if [ $SKC_PRIVATE_KEY_SUPPORT != $TRUE ]; then
     log_msg $LOG_DEBUG "PRIVATE_KEY_SUPPORT disabled, skipping LIBCURL compilation"
     exit $CODE_EXEC_SUCCESS
fi


LIBCURL_CLONE_DIR=/tmp/curl
if [ -d $LIBCURL_CLONE_DIR ]; then
	rm -rf $LIBCURL_CLONE_DIR
fi

mkdir -p $LIBCURL_CLONE_DIR

log_msg $LOG_DEBUG "LIBCURL installation started"

cmd="git clone https://github.com/curl/curl.git $LIBCURL_CLONE_DIR"
exec_linux_cmd "$cmd" $EXEC_RULE_ABORT "LIBCURL: cloning code" $CODE_EXEC_ERROR
pushd $LIBCURL_CLONE_DIR
exec_linux_cmd "git checkout ${SKC_COMPONENT_EXT_LIBCURL_VERSION}" $EXEC_RULE_ABORT "LIBCURL:checking out tag" $CODE_EXEC_ERROR
exec_linux_cmd "./buildconf" $EXEC_RULE_ABORT "LIBCURL: cloning code" $CODE_EXEC_ERROR

if [ -d ${SKC_COMPONENT_EXT_LIBCURL_INSTALL_DIR} ]; then
	rm -rf $SKC_COMPONENT_EXT_LIBCURL_INSTALL_DIR
fi
cmd="./configure --prefix=${SKC_COMPONENT_EXT_LIBCURL_INSTALL_DIR} --enable-http"
exec_linux_cmd "$cmd" $EXEC_RULE_ABORT "LIBCURL: configuring curl" $CODE_EXEC_ERROR
exec_linux_cmd "make" $EXEC_RULE_ABORT "LIBCURL: make command" $CODE_EXEC_ERROR
exec_linux_cmd "make install" $EXEC_RULE_ABORT "LIBCURL: make install command" $CODE_EXEC_ERROR
log_msg $LOG_DEBUG "LIBCURL installation successfully completed"
popd
rm -rf $LIBCURL_CLONE_DIR
