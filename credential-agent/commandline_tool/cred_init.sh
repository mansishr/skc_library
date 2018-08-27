#!/bin/bash

if [ "$1" = "" ]; then
	echo "Pleae enter: $0 <SCOPE_NAME>"
	exit -1
fi

SCOPE_NAME=$1
TOKEN_COUNT=1
CECS_IP=10.105.160.12
CECS_PORT=8080

TOKEN_FILE="./tmp/tokens.txt"

#create_scope
C_SCOPE="curl -X POST -H \"Content-Type: application/json\" -d'{\"name\":\"$SCOPE_NAME\",\"allowed_domains\":\"intel.com\", \"common_name\":\"intel.com\"}' https://$CECS_IP:$CECS_PORT/v1/main/scope/ --insecure";

echo $C_SCOPE
eval "$C_SCOPE"


TOK_BATCH="curl -X POST -H \"Content-Type: application/json\" -d'{\"batch_name\":\"batch-$SCOPE_NAME\",\"token_count\":$TOKEN_COUNT}' https://$CECS_IP:$CECS_PORT/v1/main/scope/$SCOPE_NAME/tokenbatch/  --insecure > $TOKEN_FILE"

echo $TOK_BATCH
eval "$TOK_BATCH" 

TOK_VALUE="$(awk -F, '{ print $6 }' $TOKEN_FILE | sed -e 's/\"tokens\":\[\"//' | sed -e 's/\"\]//')"
echo "TOKEN_VALUE:$TOK_VALUE"

EXEC_CMD="./cred_agent.sh \"https://$CECS_IP:$CECS_PORT/v1/main/provision/$TOK_VALUE/\" \"$TOK_VALUE\""
eval "$EXEC_CMD"

