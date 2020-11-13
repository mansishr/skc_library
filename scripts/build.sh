#!/bin/bash
script_dir=$(dirname "$(readlink -f "$0")")
conf_ops=""

# Check OS and VERSION
OS=$(cat /etc/os-release | grep ^ID= | cut -d'=' -f2)
temp="${OS%\"}"
temp="${temp#\"}"
OS="$temp"

if [ "$OS" == "rhel" ]
then
source ${script_dir}/config_rhel.ini
elif [ "$OS" == "ubuntu" ]
then
source ${script_dir}/config_ubuntu.ini
fi

if [ -f ${script_dir}/$UTILS_SOURCE ]; then
	source ${script_dir}/$UTILS_SOURCE
else
	echo -e "Utils Script not found Error, Exit." && exit 1
fi

set_log $FLAG_ENABLE "skc_library"

install_pre_requisites

if [ -d "${SKC_SGX_TOOLKIT_PATH}" ]; then
	log_msg $LOG_DEBUG "with cryptoapitoolkit v2 "
	conf_ops="${conf_ops} --with-sgx-toolkit=${SKC_SGX_TOOLKIT_PATH}"
fi

pushd ${script_dir}/../
log_msg $LOG_DEBUG "skc_library: AutoConfigure started"
exec_linux_cmd "autoreconf -i" $EXEC_RULE_ABORT "SKC: autoconf" $CODE_EXEC_ERROR
log_msg $LOG_DEBUG "skc_library: AutoConfigure completed"

log_msg $LOG_DEBUG "skc_library build started"
cmd="./configure --prefix=${SKCLIB_INSTALL_DIR} --disable-static ${conf_ops}"
exec_linux_cmd "$cmd" $EXEC_RULE_ABORT "SKC: configure cmd:$cmd" $CODE_EXEC_ERROR
exec_linux_cmd "make" $EXEC_RULE_ABORT "SKC: make" $CODE_EXEC_ERROR
log_msg $LOG_DEBUG "skc_library build completed"

log_msg $LOG_DEBUG "skc_library: Installation started"
exec_linux_cmd "make install" $EXEC_RULE_ABORT 'SKC: make install' $CODE_EXEC_ERROR
log_msg $LOG_DEBUG "skc_library: Installation completed"

exit_script $LOG_DEBUG "skc_library installed in ${SKCLIB_INSTALL_DIR}" $CODE_EXEC_SUCCESS
popd
