#!/bin/bash

SGX_STACK_VERSION=2.9
SGX_DCAP_TAG=DCAP_1.5
SGX_DRIVER_VERSION=1.22
SGX_RPM_VERSION=2.9.100.2-1
SGX_URL="https://download.01.org/intel-sgx/sgx-linux/${SGX_STACK_VERSION}/distro/rhel8.0-server"
SYSLIB_PATH=/usr/lib64
SGX_DCAP_REPO="https://github.com/intel/SGXDataCenterAttestationPrimitives.git"
SGX_TOOLKIT_URL="ssh://git@gitlab.devtools.intel.com:29418/psd-pse/crypto-api-toolkit-v2.git"
SGX_TOOLKIT_BRANCH="p11kit"
OPENSSL_DOWNLOAD_URL="https://www.openssl.org/source/openssl-1.1.1d.tar.gz"
SGXSSL_CVE_URL="https://download.01.org/intel-sgx/sgx-linux/2.9/as.ld.objdump.gold.r1.tar.gz"
SGX_INSTALL_DIR=/opt/intel
SGX_TOOLKIT_INSTALL_PREFIX=$SGX_INSTALL_DIR/sgxtoolkit
GIT_CLONE_PATH=/tmp/sgxstuff

uninstall_sgx()
{
	if [[ -d $SGX_INSTALL_DIR/sgxsdk ]]; then
		$SGX_INSTALL_DIR/sgxsdk/uninstall.sh
	fi

	if [[ -d $SGX_INSTALL_DIR/sgxpsw ]]; then
		service aesmd stop
		$SGX_INSTALL_DIR/sgxpsw/uninstall.sh
	fi

	modprobe -r intel_sgx
	dkms remove -m sgx -v $SGX_DRIVER_VERSION --all

	if [ -d /usr/src/sgx-$SGX_DRIVER_VERSION ]; then
		rm -rf /usr/src/sgx-$SGX_DRIVER_VERSION/
	fi

	if [[ -d $SGX_INSTALL_DIR/sgxssl ]]; then
		echo "Uninstalling SGX SSL"
		rm -rf $SGX_INSTALL_DIR/sgxssl
	fi

	if [[ -d $SGX_TOOLKIT_INSTALL_PREFIX ]]; then
		echo "Uninstalling SGX Toolkit"
		rm -rf $SGX_TOOLKIT_INSTALL_PREFIX
		rm -rf $SGX_INSTALL_DIR/cryptoapitoolkit/
	fi

	rpm -qa | grep 'sgx' | xargs rpm -e
	find $SYSLIB_PATH -name 'libsgx*' -exec rm -f {} \;
	find $SYSLIB_PATH -name 'libdcap*' -exec rm -f {} \;
	find $SYSLIB_PATH -name 'libquote*' -exec rm -f {} \;
	rm -rf /etc/yum.repos.d/tmp_sgxstuff_sgx_rpm_local_repo.repo
	rm -rf /usr/local/bin/ld /usr/local/bin/as /usr/local/bin/ld.gold /usr/local/bin/objdump /usr/local/bin/PCKIDRetrievalTool /usr/local/bin/enclave.signed.so /usr/local/libdcap_quoteprov.so.1
	rm -rf $GIT_CLONE_PATH
}

install_sgxssl()
{
	mkdir -p $GIT_CLONE_PATH
	pushd $GIT_CLONE_PATH
	git clone https://github.com/intel/intel-sgx-ssl.git $GIT_CLONE_PATH/sgxssl
	cd $GIT_CLONE_PATH/sgxssl
	wget -nv $SGXSSL_CVE_URL
	tar -xzf as.ld.objdump.gold.r1.tar.gz
	cp -rpf external/toolset/* /usr/local/bin
	cd openssl_source
	wget -nv $OPENSSL_DOWNLOAD_URL || exit 1
	cd ../Linux
	make all || exit 1
	make install || exit 1
	popd
}

install_sgx_components()
{
	pushd $PWD
	mkdir -p $GIT_CLONE_PATH
	pushd $GIT_CLONE_PATH
	git clone $SGX_DCAP_REPO $GIT_CLONE_PATH/
	git checkout $SGX_DCAP_TAG
	pushd driver/linux
	mkdir -p /usr/src/sgx-$SGX_DRIVER_VERSION/
	cp -rpf * /usr/src/sgx-$SGX_DRIVER_VERSION/

	dkms add -m sgx -v $SGX_DRIVER_VERSION
	dkms build -m sgx -v $SGX_DRIVER_VERSION
	dkms install -m sgx -v $SGX_DRIVER_VERSION
	modprobe intel_sgx

	cp 10-sgx.rules /etc/udev/rules.d
	groupadd sgx_prv
	usermod -a -G sgx_prv root
	udevadm trigger
	popd #driver/linux
	wget -nd -nv -rNc -e robots=off -l1 --no-parent --reject "index.html*" -A "*.bin" $SGX_URL
	chmod +x *.bin
	# install SGX SDK
	./sgx_linux_x64_sdk*.bin -prefix=$SGX_INSTALL_DIR || exit 1
	source $SGX_INSTALL_DIR/sgxsdk/environment

	wget -nv $SGX_URL/sgx_rpm_local_repo.tgz
	tar -xzf sgx_rpm_local_repo.tgz
	yum-config-manager --add-repo file://$PWD/sgx_rpm_local_repo
	yum install -y --nogpgcheck libsgx-launch libsgx-uae-service libsgx-urts

	pushd $GIT_CLONE_PATH/QuoteGeneration
	# Downlad and install the Intel signed architecture enclaves (QE, PCE)
	./download_prebuilt.sh

	# Build the Quote Generation and Quote Provider Libraries
	make quote_wrapper qpl_wrapper || exit 1

	# Since QGL make supports only ubuntu package, we need to manualy copy few include files and Quote Generation libs
        cp build/linux/*.so $SYSLIB_PATH
        cp psw/ae/data/prebuilt/libsgx_qe3.signed.so psw/ae/data/prebuilt/libsgx_pce.signed.so $SYSLIB_PATH
        cp -p quote_wrapper/common/inc/sgx_quote_3.h pce_wrapper/inc/sgx_pce.h quote_wrapper/ql/inc/sgx_dcap_ql_wrapper.h quote_wrapper/common/inc/sgx_ql_lib_common.h ../QuoteVerification/QVL/Src/AttestationLibrary/include/SgxEcdsaAttestation/QuoteVerification.h $SGX_INSTALL_DIR/sgxsdk/include/
        ln -fs $SYSLIB_PATH/libsgx_dcap_ql.so $SYSLIB_PATH/libsgx_dcap_ql.so.1
        ln -sf $SYSLIB_PATH/libsgx_default_qcnl_wrapper.so $SYSLIB_PATH/libsgx_default_qcnl_wrapper.so.1
        ln -sf $SYSLIB_PATH/libdcap_quoteprov.so $SYSLIB_PATH/libdcap_quoteprov.so.1

        cp -p qcnl/linux/sgx_default_qcnl.conf /etc
	sed -i "s|PCCS_URL=.*|PCCS_URL=https://localhost:9443/scs/sgx/certification/v1/|g" /etc/sgx_default_qcnl.conf
        sed -i "s/USE_SECURE_CERT=.*/USE_SECURE_CERT=FALSE/g" /etc/sgx_default_qcnl.conf
	popd
	# Build PCKIDRetrieval tool so that SGX Agent can extract platform collaterals
	pushd $GIT_CLONE_PATH/tools/PCKRetrievalTool
	make || exit 1
	cp -prf PCKIDRetrievalTool enclave.signed.so libdcap_quoteprov.so.1 /usr/local/bin
	popd
	popd
}

install_sgxtoolkit()
{
	rm -rf $GIT_CLONE_PATH/crypto-api-toolkit-v2
	git clone $SGX_TOOLKIT_URL $GIT_CLONE_PATH/crypto-api-toolkit-v2
	cp scripts/sgx_measurement.diff $GIT_CLONE_PATH/crypto-api-toolkit-v2
	pushd $GIT_CLONE_PATH/crypto-api-toolkit-v2
	git checkout $SGX_TOOLKIT_BRANCH
	git apply sgx_measurement.diff
	
	bash autogen.sh
	./configure --enable-p11-kit --prefix=$SGX_TOOLKIT_INSTALL_PREFIX --enable-dcap || exit 1
	make install || exit 1
	popd
}

install_prerequisites()
{
	yum update -y
	yum groupinstall -y "Development Tools"
	# RHEL 8 does not provide epel repo out of the box yet.
	yum localinstall -y https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/e/epel-release-8-8.el8.noarch.rpm
	yum install -y yum-utils python2 dkms elfutils-libelf-devel wget npm openssl-devel libcurl-devel ocaml protobuf cppunit-devel || exit 1
}

install_prerequisites
uninstall_sgx
install_sgx_components
install_sgxssl
install_sgxtoolkit
