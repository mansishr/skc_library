#!/bin/bash

SGX_STACK_VERSION=2.9.1
SGX_DCAP_TAG=DCAP_1.6
SGX_DCAP_RPM_VER=1.6.100.2-1
SGX_DRIVER_VERSION=1.33
SGX_URL="https://download.01.org/intel-sgx/sgx-linux/${SGX_STACK_VERSION}/distro/rhel8.0-server"
SYSLIB_PATH=/usr/lib64
SGX_DCAP_REPO="https://github.com/intel/SGXDataCenterAttestationPrimitives.git"
SGX_TOOLKIT_URL="ssh://git@gitlab.devtools.intel.com:29418/sst/isecl/crypto-api-toolkit.git"
SGX_TOOLKIT_BRANCH="v10+next-major"
OPENSSL_DOWNLOAD_URL="https://www.openssl.org/source/old/1.1.1/openssl-1.1.1d.tar.gz"
SGXSSL_CVE_URL="https://download.01.org/intel-sgx/sgx-linux/${SGX_STACK_VERSION}/as.ld.objdump.gold.r1.tar.gz"
SGX_INSTALL_DIR=/opt/intel
SGX_TOOLKIT_INSTALL_PREFIX=$SGX_INSTALL_DIR/sgxtoolkit
SGXSSL_TAG=lin_2.9.1_1.1.1d
GIT_CLONE_PATH=/tmp/sgxstuff
P11_KIT_PATH=/usr/include/p11-kit-1/p11-kit/
KDIR=/lib/modules/$(uname -r)/build
INKERNEL_SGX=$(cat $KDIR/.config | grep "CONFIG_INTEL_SGX=y")

uninstall_sgx()
{
	if [[ -d $SGX_INSTALL_DIR/sgxsdk ]]; then
		$SGX_INSTALL_DIR/sgxsdk/uninstall.sh
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
	rm -rf /etc/yum.repos.d/tmp_sgxstuff_sgx_rpm_local_repo.repo
	rm -rf /usr/local/bin/ld /usr/local/bin/as /usr/local/bin/ld.gold /usr/local/bin/objdump
	rm -rf $GIT_CLONE_PATH
}

install_sgxssl()
{
	mkdir -p $GIT_CLONE_PATH
	pushd $GIT_CLONE_PATH
	git clone https://github.com/intel/intel-sgx-ssl.git $GIT_CLONE_PATH/sgxssl
	cd $GIT_CLONE_PATH/sgxssl
	git checkout $SGXSSL_TAG
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
	wget -nd -nv -rNc -e robots=off -l1 --no-parent --reject "index.html*" -A "*.bin" $SGX_URL
	chmod +x *.bin
	# install SGX DCAP Driver if SGX Support is not enabled in kernel
	if [ -z "$INKERNEL_SGX" ]; then
		echo "Installing dcap driver"
		./sgx_linux_x64_driver_${SGX_DRIVER_VERSION}.bin -prefix=$SGX_INSTALL_DIR || exit 1
	else
		echo "Found inbuilt sgx driver, skipping dcap driver installation"
	fi
	# install SGX SDK
	./sgx_linux_x64_sdk*.bin -prefix=$SGX_INSTALL_DIR || exit 1
	source $SGX_INSTALL_DIR/sgxsdk/environment

	# Install SGX PSW
	wget -nv $SGX_URL/sgx_rpm_local_repo.tgz
	tar -xzf sgx_rpm_local_repo.tgz
	yum-config-manager --add-repo file://$PWD/sgx_rpm_local_repo
	yum install -y --nogpgcheck libsgx-launch libsgx-uae-service libsgx-urts

	# Install SGX DCAP QGL/QPL libraries
	pushd $GIT_CLONE_PATH/QuoteGeneration
        cp -p pce_wrapper/inc/sgx_pce.h $SGX_INSTALL_DIR/sgxsdk/include/
	./download_prebuilt.sh
	make rpm_pkg
	pushd installer/linux/rpm
	rpm -ivh libsgx-ae-qve-${SGX_DCAP_RPM_VER}.el8.x86_64.rpm libsgx-dcap-ql-${SGX_DCAP_RPM_VER}.el8.x86_64.rpm libsgx-dcap-ql-devel-${SGX_DCAP_RPM_VER}.el8.x86_64.rpm libsgx-dcap-default-qpl-devel-${SGX_DCAP_RPM_VER}.el8.x86_64.rpm libsgx-dcap-default-qpl-${SGX_DCAP_RPM_VER}.el8.x86_64.rpm
	popd

	sed -i "s|PCCS_URL=.*|PCCS_URL=https://localhost:9000/scs/sgx/certification/v1/|g" /etc/sgx_default_qcnl.conf
	sed -i "s/USE_SECURE_CERT=.*/USE_SECURE_CERT=FALSE/g" /etc/sgx_default_qcnl.conf
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
	./configure --with-p11-kit-path=$P11_KIT_PATH --prefix=$SGX_TOOLKIT_INSTALL_PREFIX --enable-dcap || exit 1
	make install || exit 1
	popd
}

install_prerequisites()
{
	yum update -y
	yum groupinstall -y "Development Tools"
	# RHEL 8 does not provide epel repo out of the box yet.
	yum localinstall -y https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/e/epel-release-8-8.el8.noarch.rpm
	yum install -y yum-utils python3 kernel-devel dkms elfutils-libelf-devel wget libcurl-devel ocaml protobuf cppunit-devel p11-kit-devel || exit 1
}

install_prerequisites
uninstall_sgx
install_sgx_components
install_sgxssl
install_sgxtoolkit
