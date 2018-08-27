#!/bin/bash

EXEC_FILE=$0
CRED_URL=$1
TOKEN_VALUE=$2


CONF_FILE_LOCATION="./conf"
CRED_CONF_FILE="$CONF_FILE_LOCATION/main.conf"

EXEC_RULE_ABORT=1
EXEC_RULE_WARN=2

CODE_ERROR='\033[0;31m' #RED_COLOR
CODE_OK='\033[0;32m'  #GREEN_COLOR
CODE_WARNING='\033[0;33m' #BROWN/ORANGE_COLOR   
CODE_NC='\033[0m' #NO_COLOR`

LOG_OK=0
LOG_ERROR=1
LOG_WARN=2
LOG_DEBUG=3

declare -a LOG_PREFIX=("${CODE_OK}INFO:" "${CODE_ERROR}ERROR:" "${CODE_WARNING}WARN:"  "${CODE_OK}DEBUG:")
declare -a LOG_SUFFIX=(" successful${CODE_NC}" " failed!${CODE_NC}" " not successful !${CODE_NC}"  ".${CODE_NC}")

log_msg()
{
	LOG_LEVEL=$1
	LOG_MSG=$2
	echo -e "${LOG_PREFIX[$LOG_LEVEL]} ${LOG_MSG} ${LOG_SUFFIX[$LOG_LEVEL]}"
}

exit_script()
{
	log_msg $LOG_ERROR "Scrit execution"
	exit -1
}

if [ "$CRED_URL" = "" ] || [ "$TOKEN_VALUE" = "" ]; then
	log_msg $LOG_DEBUG "Please execute like $EXEC_FILE <CRED_URL> <TOKEN_VALUE>"
	exit_script
fi

read_conf_file()
{
	if [ -f $CRED_CONF_FILE ]; then
		source $CRED_CONF_FILE
	else 
		log_msg $LOG_ERROR "$CRED_CONF_FILE read"
	fi
}

check_last_cmd_exec_status()
{
	EXEC_CMD=$1
	EXEC_RULE=$2
	LOG_MSG=$3

	eval "$EXEC_CMD"
	LAST_EXEC_STAT=$?

	if [ $LAST_EXEC_STAT -ne 0 ] && [ $EXEC_RULE -eq $RULE_ABORT ]; then
		log_msg $LOG_ERROR "$LOG_MSG"
		exit_script
	elif [ $LAST_EXEC_STAT -ne 0 ] && [ $EXEC_RULE -eq $RULE_WARN ]; then
		log_msg $LOG_WARN "$LOG_MSG"
	else
		log_msg $LOG_DEBUG "$LOG_MSG : CMD:$EXEC_CMD"
	fi
}

create_usable_directories()
{
	RM_DIR="rm -rf $PRIV_KEY_LOCATION $PEM_FILE_LOCATION $TMP_LOCATION"
	check_last_cmd_exec_status "$RM_DIR" "$RULE_ABORT" "Folder creation"
	MK_DIR="mkdir -p $PRIV_KEY_LOCATION $PEM_FILE_LOCATION $TMP_LOCATION"
	check_last_cmd_exec_status "$MK_DIR" "$RULE_ABORT" "Folder creation"
}

gen_csr_req()
{
	CSR_CMD="openssl req -newkey $KEY_TYPE:$KEY_BITS -nodes -keyout $PRIVATE_KEY_FILE -out $CSR_PEM_FILE -outform pem -subj \"$CERT_SUB\""
	check_last_cmd_exec_status "$CSR_CMD" "$RULE_ABORT" "CSR Request"
}

sign_with_cred_service()
{
	SIGN_CMD="curl -X GET ${CRED_URL} --data-binary @$CSR_PEM_FILE -H 'Content-Type: application/x-pem-file' -H 'Accept: application/x-pem-file' -H \"Authorization: Bearer $TOKEN_VALUE\" -k > $CERT_PEM_FILE"
	check_last_cmd_exec_status "$SIGN_CMD" "$RULE_ABORT" "Sign with Credential Service"
}

renew_certificate()
{
	gen_csr_req
	RENEW_CERTIFICATE="curl -X POST ${CRED_URL} --data-binary @CSR_PEM_FILE -H 'Content-Type: application/x-pem-file' -H 'Accept: application/x-pem-file' -k > $CERT_PEM_FILE"
	check_last_cmd_exec_status "$RENEW_CERTIFICATE" "$RULE_ABORT" "Renew Certificate with Credential Service"
}


read_conf_file
create_usable_directories
gen_csr_req
sign_with_cred_service
#renew_certificate

