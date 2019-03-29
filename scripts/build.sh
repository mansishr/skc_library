#!/bin/bash
#set -x
script_dir=$(dirname $0)
source ${script_dir}/config.ini

if [ -f ${script_dir}/$UTILS_SOURCE ]; then
    source ${script_dir}/$UTILS_SOURCE
else
    echo -e "Utils Script not found Error, Exit." && exit 1
fi


set_log $FLAG_ENABLE "DHSM2_WORKLOAD"


check_pre_condition $FLAG_ENABLE 
if [ $? -ne $CODE_EXEC_SUCCESS ]; then
	exit_script $LOG_ERROR "Pre conditions not satisfied" $CODE_ERROR
fi

install_pre_requisites
if [ $? -ne $CODE_EXEC_SUCCESS ]; then
	exit_script $LOG_ERROR "Pre-requisties installation" $CODE_ERROR
fi


download_deps

openssl_lib_cnt=$(get_file_count "libssl.so.$DHSM2_COMPONENT_REQ_LIB_OPENSSL_VER*")
curl_lib_cnt=$(get_file_count "libcurl.so.$DHSM2_COMPONENT_REQ_LIB_CURL_VER*")
log_msg $LOG_DEBUG "Count: ssl: $openssl_lib_cnt, curl: $curl_lib_cnt"

if [ $openssl_lib_cnt -eq 0 ] || [ $curl_lib_cnt -eq 0 ]; then
    log_msg $LOG_DEBUG "Downloading and Installing External components"
    download_external_components $DHSM2_COMPONENT_EXT_COMPONENT_DIR
    install_external_components $DHSM2_COMPONENT_EXT_COMPONENT_DIR
fi

echo $PATH
mkdir -p $PWD/safestringlib/obj
mkdir -p $PWD/safestringlib/objtest
$(exec_linux_cmd "make clean -C ./safestringlib" $EXEC_RULE_ABORT "Make" $CODE_EXEC_SUCCESS)
$(exec_linux_cmd "make -C ./safestringlib" $EXEC_RULE_ABORT "Make" $CODE_EXEC_SUCCESS)
log_msg $LOG_DEBUG "Safestring  lib: Compilation completed"

log_msg $LOG_DEBUG "KeyAgent: AutoConfigure started"
$(exec_linux_cmd "autoreconf -i" $EXEC_RULE_ABORT "autoconf" $CODE_EXEC_SUCCESS)
log_msg $LOG_DEBUG "KeyAgent: AutoConfigure completed"		

log_msg $LOG_DEBUG "KeyAgent: compilation started"
if [ -z "${DHSM2_COMPONENT_EXT_OPENSSL_INSTALL_DIR}" ] || [ -z "${DHSM2_COMPONENT_EXT_LIBCURL_INSTALL_DIR}" ]; then
    log_msg $LOG_DEBUG "Openssl and libcurl paths are not given"
    $(exec_linux_cmd "./configure --prefix=${DHSM2_COMPONENT_INSTALL_DIR} --disable-static --disable-gost" $EXEC_RULE_ABORT "configure" $CODE_EXEC_SUCCESS)
else
    log_msg $LOG_DEBUG "Openssl and libcurl paths are given"
    export LD_LIBRARY_PATH=${DHSM2_COMPONENT_EXT_OPENSSL_INSTALL_DIR}/lib:${DHSM2_COMPONENT_EXT_LIBCURL_INSTALL_DIR}/lib:${LD_LIBRARY_PATH}
    $(exec_linux_cmd "./configure --prefix=${DHSM2_COMPONENT_INSTALL_DIR} --disable-static --disable-gost --with-openssl=${DHSM2_COMPONENT_EXT_OPENSSL_INSTALL_DIR} --with-libcurl=${DHSM2_COMPONENT_EXT_LIBCURL_INSTALL_DIR}" $EXEC_RULE_ABORT "configure" $CODE_EXEC_SUCCESS)
fi
log_msg $LOG_DEBUG "KeyAgent: compilation completed"

log_msg $LOG_DEBUG "KeyAgent build started"
$(exec_linux_cmd "make" $EXEC_RULE_ABORT "make" $CODE_EXEC_SUCCESS)
log_msg $LOG_DEBUG "KeyAgent build completed"

log_msg $LOG_DEBUG "KeyAgent: Installation started"
$(exec_linux_cmd "make install" $EXEC_RULE_ABORT "make install" $CODE_EXEC_SUCCESS)
log_msg $LOG_DEBUG "KeyAgent: Installation completed"

exit_script $LOG_DEBUG "Workload component installed in path:${DHSM2_INSTALL_DIR} successfully" $CODE_EXEC_SUCCESS
