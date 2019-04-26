#!/bin/bash
script_dir=$(dirname "$(readlink -f "$0")")

source ${script_dir}/config.ini

if [ -f ${script_dir}/$UTILS_SOURCE ]; then
    source ${script_dir}/$UTILS_SOURCE
else
    echo -e "Utils Script not found Error, Exit." && exit 1
fi


set_log $FLAG_ENABLE "DHSM2_WORKLOAD"

install_pre_requisites "devOps"
check_pre_condition $FLAG_ENABLE 
install_pre_requisites "dev"


bash ${script_dir}/pre-req.sh "${script_dir}" "$1" 

pushd ${script_dir}/../
log_msg $LOG_DEBUG "KeyAgent: AutoConfigure started"
exec_linux_cmd "autoreconf -i" $EXEC_RULE_ABORT "autoconf" $CODE_EXEC_ERROR
log_msg $LOG_DEBUG "KeyAgent: AutoConfigure completed"		

log_msg $LOG_DEBUG "KeyAgent: compilation started"
if [ -d "${DHSM2_SGX_TOOLKIT_PATH}" ]; then
	
   log_msg $LOG_DEBUG "with sgx toolkit "		
   exec_linux_cmd "./configure --prefix=${DHSM2_COMPONENT_INSTALL_DIR} --disable-static --with-sgx-toolkit=${DHSM2_SGX_TOOLKIT_PATH}" $EXEC_RULE_ABORT "configure" $CODE_EXEC_ERROR
else
   log_msg $LOG_DEBUG "without sgx toolkit "		
   exec_linux_cmd "./configure --prefix=${DHSM2_COMPONENT_INSTALL_DIR} --disable-static" 
			$EXEC_RULE_ABORT "configure" $CODE_EXEC_ERROR
fi
log_msg $LOG_DEBUG "KeyAgent: compilation completed"

log_msg $LOG_DEBUG "KeyAgent build started"
exec_linux_cmd "make clean" $EXEC_RULE_ABORT 'make clean' $CODE_EXEC_ERROR
exec_linux_cmd "make" $EXEC_RULE_ABORT "make" $CODE_EXEC_ERROR
log_msg $LOG_DEBUG "KeyAgent build completed"

log_msg $LOG_DEBUG "KeyAgent: Installation started"
exec_linux_cmd "make install" $EXEC_RULE_ABORT 'make install' $CODE_EXEC_ERROR
log_msg $LOG_DEBUG "KeyAgent: Installation completed"

exit_script $LOG_DEBUG "Workload component installed in path:${DHSM2_INSTALL_DIR} successfully" $CODE_EXEC_SUCCESS
popd
