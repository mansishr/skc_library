#!/bin/bash

SGX_STACK_VERSION=2.7.1
SGX_DCAP_TAG=DCAP_1.3.1
SGX_DRIVER_VERSION=1.3.1
SGX_URL="https://download.01.org/intel-sgx/sgx-linux/${SGX_STACK_VERSION}/distro/rhel8.0-server"
SYSLIB_PATH=/usr/lib64
SGX_DCAP_REPO="https://github.com/intel/SGXDataCenterAttestationPrimitives.git"
SGX_TOOLKIT_BRANCH="v6+next-major"
SGX_TOOLKIT_URL="ssh://git-amr-1.devtools.intel.com:29418/distributed_hsm-sgxtoolkit"
OPENSSL_DOWNLOAD_URL="https://www.openssl.org/source/openssl-1.1.1d.tar.gz"
SGX_TOOLKIT_INSTALL_PREFIX="/opt/intel/sgxtoolkit"
GIT_CLONE_PATH=/tmp/sgxstuff

uninstall_sgx()
{
	if [[ -d /opt/intel/sgxsdk ]]; then
		/opt/intel/sgxsdk/uninstall.sh
	fi

	if [[ -d /opt/intel/sgxpsw ]]; then
		service aesmd stop
		/opt/intel/sgxpsw/uninstall.sh
	fi

	modprobe -r intel_sgx
	dkms remove -m sgx -v $SGX_DRIVER_VERSION --all

	if [ -d /usr/src/sgx-$SGX_DRIVER_VERSION ]; then
		rm -rf /usr/src/sgx-$SGX_DRIVER_VERSION/
	fi

	if [[ -d /opt/intel/sgxssl ]]; then
		echo "Uninstalling SGX SSL"
		rm -rf /opt/intel/sgxssl
	fi

	if [[ -d $SGX_TOOLKIT_INSTALL_PREFIX ]]; then
		echo "Uninstalling SGX Toolkit"
		rm -rf $SGX_TOOLKIT_INSTALL_PREFIX
		rm -rf /opt/intel/cryptoapitoolkit/
	fi

	if [[ -d /opt/intel/pccs ]]; then
		/opt/intel/pccs/uninstall.sh
		rm -rf /opt/intel/pccs
		rm /etc/sgx_default_qcnl.conf
	fi

	find $SYSLIB_PATH -name 'libsgx*' -exec rm -f {} \;
	find $SYSLIB_PATH -name 'libdcap*' -exec rm -f {} \;
	rm -rf $GIT_CLONE_PATH
}

install_pccs()
{
	pushd $GIT_CLONE_PATH/QuoteGeneration
        cp -p qcnl/linux/sgx_default_qcnl.conf /etc
        sed -i "s/USE_SECURE_CERT=.*/USE_SECURE_CERT=FALSE/g" /etc/sgx_default_qcnl.conf

        cp -r pccs /opt/intel
        pushd /opt/intel/pccs

        openssl genrsa 2048 > private.pem
        openssl req -new -key private.pem -out csr.pem -subj "/CN=localhost"
        openssl x509 -req -days 365 -in csr.pem -signkey private.pem -out file.crt
	
	# These are Sandbox (Preprod Intel PCS Server) API Subscription Ket and Url Values
	sed -i '/"ApiKey":/ s/"ApiKey":[^,]*/"ApiKey": "9e0153b3f0c948d9ade866635f039e1e"/' config/default.json
	sed -i '/"proxy":/ s/"proxy":[^,]*/"proxy": "http:\/\/proxy-us.intel.com:911"/' config/default.json
	sed -i '/"uri":/ s/"uri":[^,]*/"uri": "https:\/\/sbx.api.trustedservices.intel.com\/sgx\/certification\/v2\/"/' config/default.json

        ./install.sh
        popd #/opt/intel/pccs

        popd #GIT_CLONE_PATH
}

install_sgxssl()
{
	mkdir -p $GIT_CLONE_PATH
	pushd $GIT_CLONE_PATH
	git clone https://github.com/intel/intel-sgx-ssl.git $GIT_CLONE_PATH/sgxssl
	cd $GIT_CLONE_PATH/sgxssl
	git checkout lin_2.5_1.1.1d
	cd openssl_source
	wget $OPENSSL_DOWNLOAD_URL || exit 
	cd ../Linux
	make clean all || exit 1
	make install || exit 1
	popd
}

install_sgx_components()
{
	mkdir -p $GIT_CLONE_PATH
	pushd  $GIT_CLONE_PATH
	git clone $SGX_DCAP_REPO $GIT_CLONE_PATH/
	git checkout $SGX_DCAP_TAG
	pushd driver/linux
	mkdir -p /usr/src/sgx-$SGX_DRIVER_VERSION/
	cp -rpf * /usr/src/sgx-$SGX_DRIVER_VERSION/

	dkms add -m sgx -v $SGX_DRIVER_VERSION
	dkms build -m sgx -v $SGX_DRIVER_VERSION
	dkms install -m sgx -v $SGX_DRIVER_VERSION
	modprobe intel_sgx

	popd #driver/linux

	wget -nd -rNc -e robots=off -l1 --no-parent --reject "index.html*" -A "*.bin" $SGX_URL
	chmod +x *.bin
	# install SGX PSW including aesmd
	./sgx_linux_x64_psw*.bin || exit 1
	# install SGX SDK
	./sgx_linux_x64_sdk*.bin -prefix=/opt/intel || exit 1
	
	rm -rf *.bin
	cd  $GIT_CLONE_PATH/QuoteGeneration
	# Downlad and install the Intel signed architecture enclaves (QE, PCE)
	./download_prebuilt.sh

	# Build the Quote Generation and Quote Provider Libraries
	make quote_wrapper qpl_wrapper || exit 1

	# Since QGL make supports only ubuntu package, we need to manualy copy few include files and Quote Generation libs
	cp build/linux/*.so $SYSLIB_PATH
	cp psw/ae/data/prebuilt/libsgx_qe3.signed.so psw/ae/data/prebuilt/libsgx_pce.signed.so $SYSLIB_PATH
	cp -p quote_wrapper/common/inc/sgx_quote_3.h pce_wrapper/inc/sgx_pce.h quote_wrapper/ql/inc/sgx_dcap_ql_wrapper.h quote_wrapper/common/inc/sgx_ql_lib_common.h ../QuoteVerification/QVL/Src/AttestationLibrary/include/SgxEcdsaAttestation/QuoteVerification.h /opt/intel/sgxsdk/include/
	ln -fs $SYSLIB_PATH/libsgx_dcap_ql.so $SYSLIB_PATH/libsgx_dcap_ql.so.1
	ln -sf $SYSLIB_PATH/libsgx_default_qcnl_wrapper.so $SYSLIB_PATH/libsgx_default_qcnl_wrapper.so.1
	ln -sf $SYSLIB_PATH/libdcap_quoteprov.so $SYSLIB_PATH/libdcap_quoteprov.so.1

	# Build PCKIDRetrieval tool so that SGX Agent can extract platform collaterals
	cd $GIT_CLONE_PATH/tools/PCKRetrievalTool/
	make || exit 1
	cp -prf PCKIDRetrievalTool enclave.signed.so libdcap_quoteprov.so.1 /usr/local/bin
	popd
}

install_sgxtoolkit()
{
	mkdir -p $SGX_TOOLKIT_INSTALL_PREFIX
	rm -rf $GIT_CLONE_PATH/distributed_hsm-sgxtoolkit

	git clone $SGX_TOOLKIT_URL $GIT_CLONE_PATH/distributed_hsm-sgxtoolkit
	cp scripts/sgx_measurement.diff $GIT_CLONE_PATH/distributed_hsm-sgxtoolkit
	pushd  $GIT_CLONE_PATH/distributed_hsm-sgxtoolkit
	git checkout $SGX_TOOLKIT_BRANCH
	git apply sgx_measurement.diff
	
	bash autogen.sh
	./configure --prefix=$SGX_TOOLKIT_INSTALL_PREFIX --with-dcap-path=$GIT_CLONE_PATH
	make install || exit 1
	popd
}

install_prerequisites()
{
	# On a fresh box, this is required for following updates to work
	yum update -y
	yum groupinstall -y "Development Tools"
	# RHEL 8 does not provide epel repo out of the box yet.
	yum localinstall -y https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/e/epel-release-8-8.el8.noarch.rpm
	yum install -y python2 dkms kernel-devel-$(uname -r) elfutils-libelf-devel wget npm libcurl-devel ocaml protobuf || exit 1
}

install_prerequisites
uninstall_sgx
install_sgx_components
install_sgxssl
install_pccs
install_sgxtoolkit
