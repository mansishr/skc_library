#!/bin/bash

script_dir=$(dirname "$(readlink -f "$0")")
source ${script_dir}/config.ini

if [ -f ${script_dir}/$UTILS_SOURCE ]; then
    source ${script_dir}/$UTILS_SOURCE
else
    echo -e "common-utils.sh not found." && exit 1
fi

uninstall_skc_library()
{
    $(exec_linux_cmd "crontab -l | grep -v 'credential_agent.ini' | crontab - " $EXEC_RULE_WARN "Removing credential agent crontab" $CODE_EXEC_SUCCESS)
    $(exec_linux_cmd "rm -rf ${SKC_CRED_AGENT_LOG_PATH}" $EXEC_RULE_WARN "Removing credential agent logs" ${CODE_EXEC_ERROR})
    $(exec_linux_cmd "rm -rf ${SKCLIB_INSTALL_DIR}" $EXEC_RULE_WARN "Removing skc_library installation" $CODE_EXEC_SUCCESS)
}

uninstall_skc_library
