#!/bin/bash
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

log_msg $LOG_DEBUG "KeyAgent: AutoConfigure started"
$(exec_linux_cmd "autoreconf -i" $EXEC_RULE_ABORT "autoconf" $CODE_EXEC_SUCCESS)
log_msg $LOG_DEBUG "KeyAgent: AutoConfigure completed"		

log_msg $LOG_DEBUG "KeyAgent: compilation started"
$(exec_linux_cmd "./configure --prefix=${DHSM2_COMPONENT_INSTALL_DIR} --disable-static --disable-gost" $EXEC_RULE_ABORT "configure" $CODE_EXEC_SUCCESS)
log_msg $LOG_DEBUG "KeyAgent: compilation completed"

log_msg $LOG_DEBUG "KeyAgent build started"
$(exec_linux_cmd "make" $EXEC_RULE_ABORT "make" $CODE_EXEC_SUCCESS)
log_msg $LOG_DEBUG "KeyAgent build completed"

log_msg $LOG_DEBUG "KeyAgent: Installation started"
$(exec_linux_cmd "make install" $EXEC_RULE_ABORT "make install" $CODE_EXEC_SUCCESS)
log_msg $LOG_DEBUG "KeyAgent: Installation completed"

exit_script $LOG_DEBUG "Workload component installed in path:${DHSM2_INSTALL_DIR} successfully" $CODE_EXEC_SUCCESS
