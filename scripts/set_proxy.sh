#!/bin/bash
#set_proxy.sh

# Access build parameters
# For future we could read from build parameters file 
#if [ -f /opt/dhsmBuild/dhsm_build_params ]; then
#    echo "Read from build parameters"
#    source /opt/dhsmBuild/dhsm_build_params
#else
	echo "Read local configuration"
	source install_config
#fi

if [[ ! -z "${HTTP_PROXY_URL}" ]]; then
        export http_proxy=$HTTP_PROXY_URL
	echo $http_proxy
fi

if [[ ! -z "$HTTPS_PROXY_URL" ]]; then
        export https_proxy=$HTTPS_PROXY_URL   	
	echo $https_proxy
fi
