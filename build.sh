#!/bin/bash

    echo -ne "${NC}Building Key Agent: "
	
	echo "INFO: Set proxy"
	source set_proxy.sh

	echo "setting http proxy:"$http_proxy
	echo "setting htpps proxy:"$https_proxy
    	
	echo -ne "${NC}Installing pre-requisites: "
	yum install curl-devel openssl-devel glib Jsoncpp-devel libgda-devel libgda-sqlite -y
	
	echo "INFO: KeyAgent: AutoConfigure started"
    	autoreconf -i
	echo "INFO: KeyAgent: AutoConfigure completed"		

	echo "INFO: KeyAgent: compilation started"
	./configure --prefix=/opt/dhsm2/workload --enable-always-build-tests
	echo "INFO: KeyAgent: compilation completed"

	echo "INFO: KeyAgent build started"
	make 
	echo "INFO: KeyAgent build completed"

	echo "INFO: KeyAgent: Installation started"
	make install
	echo "INFO: KeyAgent: Installation completed"
	
	exit 0