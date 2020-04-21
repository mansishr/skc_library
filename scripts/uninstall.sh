#!/bin/bash

script_dir=$(dirname "$(readlink -f "$0")")
source ${script_dir}/config.ini

if [ -f ${script_dir}/$UTILS_SOURCE ]; then
    source ${script_dir}/$UTILS_SOURCE
else
    echo -e "Utils Script not found Error, Exit." && exit 1
fi

remove_existing_workload_code()
{
    $(exec_linux_cmd "crontab -l | grep -v 'credential_agent.ini' | crontab - " $EXEC_RULE_WARN "Removing credential agent crontab" $CODE_EXEC_SUCCESS)
    $(exec_linux_cmd "rm -rf ${SKC_CRED_AGENT_LOG_PATH}" $EXEC_RULE_WARN "Removing log dir" ${CODE_EXEC_ERROR})
    $(exec_linux_cmd "rm -rf ${SKC_COMPONENT_INSTALL_DIR}" $EXEC_RULE_WARN "Removing Workload Installed code" $CODE_EXEC_SUCCESS)
}

remove_existing_workload_code
