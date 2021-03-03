#!/bin/bash
source skc_library.conf
SKCLIB_INST_PATH=/opt/skc
KMS_NPM_PATH=$SKCLIB_INST_PATH/etc/kms_npm.ini
CREDENTIAL_PATH=$SKCLIB_INST_PATH/etc/credential_agent.ini

echo "################ Install Admin user token....  #################"
INSTALL_ADMIN_TOKEN=`curl --noproxy "*" -k -X POST https://$AAS_IP:$AAS_PORT/aas/v1/token -d '{"username": "'"$INSTALL_ADMIN_USERNAME"'", "password": "'"$INSTALL_ADMIN_PASSWORD"'" }'`
if [ $? -ne 0 ]; then
 echo "############ Could not get token for Install Admin User ####################"
 exit 1
fi

update_credential_ini()
{
	sed -i "s|server=.*|server=https:\/\/$KBS_HOSTNAME:$KBS_PORT|g" $KMS_NPM_PATH
	sed -i "s|request_params=.*|request_params=\"\/CN=$SKC_USER\"|g" $CREDENTIAL_PATH
	sed -i "s|server=.*|server=$CMS_IP|g" $CREDENTIAL_PATH
	sed -i "s|port=.*|port=$CMS_PORT|g" $CREDENTIAL_PATH
	sed -i "s|^token=.*|token=\"$INSTALL_ADMIN_TOKEN\"|g" $CREDENTIAL_PATH	
	curl -k -H 'Accept:application/x-pem-file' https://$CMS_IP:$CMS_PORT/cms/v1/ca-certificates > $SKCLIB_INST_PATH/store/cms-ca.cert
}	

run_credential_agent()
{
	$SKCLIB_INST_PATH/bin/credential_agent_init
	if [ $? -ne 0 ]
	then
		echo "credential init failed"
		exit 1
	fi
}

update_credential_ini
run_credential_agent
