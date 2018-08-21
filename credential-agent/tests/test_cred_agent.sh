#!/bin/sh
agent_conf_file="__PREFIX__/etc/credential_agent.ini"
agent_commandline_tool="__PREFIX__/bin/credential_agent_tool"

readonly UTIL_SCRIPT="__PREFIX__/bin/credential-agent/common_utils"

if [ -f $UTIL_SCRIPT ]; then
	source $UTIL_SCRIPT
	set_log $FLAG_ENABLE
else
	echo "$UTIL_SCRIPT not found"
	exit $CODE_IO_FAILURE
fi

execute_test()
{
	local cmd=$1	
	local expected_ret=$2
	local test_desc=$3

	eval "$cmd"
	local ret=$?

	if [[ $ret -eq $expected_ret ]]; then
		log_msg $LOG_OK "Test Case $test_desc"
	else
		log_msg $LOG_ERROR "Test Case $test_desc"
	fi
}

get_additional_command()
{
	local cmd="$1"
	if [ ! -z "$2" ] && [ "$2" = "verbose" ]; then
		cmd="$cmd --verbose"
	fi
	if [ ! -z "$3" ] && [ "$3" = "force" ]; then
		cmd="$cmd --force"
	fi
	if [ ! -z "$4" ] && [ "$4" =  "config" ]; then
		cmd="$cmd --config $5"
	fi
	echo $cmd
}

get_issue_cert_command()
{
	local cmd="$agent_commandline_tool --get-certificate"
	cmd=$(get_additional_command "$cmd" "$1" "$2" "$3" "$4")
	echo $cmd
}

get_renew_cert_command()
{
	local cmd="$agent_commandline_tool --renew-certificate"
	cmd=$(get_additional_command "$cmd" "$1" "$2" "$3" "$4")
	echo $cmd
}


#./test_agent <CS_IP> <TOKEN>
if [ -z "$1" ] || [ -z "$2" ]; then
	log_msg $LOG_WARN "Invalid argurement: $0 <CS_IP> <TOKEN>"
	exit -1
fi
cs_ip=$1
token=$2

update_agent_config "$cs_ip" "$token"  "$agent_conf_file"

#AGENT_ISSUE_CERT
execute_test "$(get_issue_cert_command verbose force)" $CODE_EXEC_SUCCESS "1: Issue Certificate"
execute_test "$(get_issue_cert_command \"\" force)" $CODE_EXEC_ERROR "2: Issue Certificate"
#AGENT_RENEW_CERT
execute_test "$(get_renew_cert_command \"\" force)" $CODE_EXEC_SUCCESS "3: Renew Certificate"
execute_test "$(get_renew_cert_command \"\" force)" $CODE_EXEC_SUCCESS "3: Renew Certificate"
#ERROR_HANDLING
execute_test "$(get_issue_cert_command verbose force config junk_file)" $CODE_IO_FAILURE "4: Issue Certificate with invalid config file"
execute_test "$agent_commandline_tool"  $CODE_PARSE_ERROR "5: Operation not specified"
execute_test "$(get_issue_cert_command \"\" )" $CODE_EXEC_WARN "6: Issue Certificate without force"
execute_test "$(get_renew_cert_command)" $CODE_EXEC_ERROR "7: Renew Certificate without force"
