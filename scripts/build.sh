#!/bin/bash
script_dir=$(dirname "$(readlink -f "$0")")
conf_ops=""

source ${script_dir}/config.ini

if [ -f ${script_dir}/$UTILS_SOURCE ]; then
    source ${script_dir}/$UTILS_SOURCE
else
    echo -e "Utils Script not found Error, Exit." && exit 1
fi

set_log $FLAG_ENABLE "SKC_WORKLOAD"

check_pre_condition $FLAG_ENABLE 
install_pre_requisites

bash ${script_dir}/pre-req.sh "${script_dir}" "$1" 

if [ $SKC_PRIVATE_KEY_SUPPORT -eq $TRUE ] && [ -d ${SKC_COMPONENT_EXT_LIBCURL_INSTALL_DIR} ]; then
   	log_msg $LOG_DEBUG "with libcurl "		
	conf_ops=" --with-libcurl=${SKC_COMPONENT_EXT_LIBCURL_INSTALL_DIR}"
fi
if [ -d "${SKC_SGX_TOOLKIT_PATH}" ]; then
   	log_msg $LOG_DEBUG "with sgx toolkit "		
	conf_ops="${conf_ops} --with-sgx-toolkit=${SKC_SGX_TOOLKIT_PATH}"
fi

pushd ${script_dir}/../
log_msg $LOG_DEBUG "KeyAgent: AutoConfigure started"
exec_linux_cmd "autoreconf -i" $EXEC_RULE_ABORT "SKC: autoconf" $CODE_EXEC_ERROR
log_msg $LOG_DEBUG "KeyAgent: AutoConfigure completed"		

log_msg $LOG_DEBUG "KeyAgent: compilation started"

cmd="./configure --prefix=${SKC_COMPONENT_INSTALL_DIR} --disable-static ${conf_ops}"
exec_linux_cmd "$cmd" $EXEC_RULE_ABORT "SKC: configure cmd:$cmd" $CODE_EXEC_ERROR
log_msg $LOG_DEBUG "KeyAgent: compilation completed"

log_msg $LOG_DEBUG "KeyAgent build started"
exec_linux_cmd "make clean" $EXEC_RULE_ABORT 'SKC: make clean' $CODE_EXEC_ERROR
exec_linux_cmd "make" $EXEC_RULE_ABORT "SKC: make" $CODE_EXEC_ERROR
log_msg $LOG_DEBUG "KeyAgent build completed"

log_msg $LOG_DEBUG "KeyAgent: Installation started"
exec_linux_cmd "make install" $EXEC_RULE_ABORT 'SKC: make install' $CODE_EXEC_ERROR
log_msg $LOG_DEBUG "KeyAgent: Installation completed"

exit_script $LOG_DEBUG "Workload component installed in path:${SKC_INSTALL_DIR} successfully" $CODE_EXEC_SUCCESS
popd
