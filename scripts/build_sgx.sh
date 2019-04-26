#!/bin/bash
yum install gcc-c++ git -y
OPENSSL_URL="https://www.openssl.org/source/openssl-1.1.1a.tar.gz"
SGX_DOWNLOAD_URL="https://download.01.org/intel-sgx/linux-2.5/rhel7.4-server/"
SGX_TOOLKIT_BRANCH="v3+next-major"
SGX_TOOLKIT_INSTALL_PREFIX="/opt/intel/sgxtoolkit"
GIT_CLONE_PATH=/tmp/sgxstuff


uninstall_sgx()
{
	if [ -d /opt/intel/sgxdriver ]; then
	  	echo "Uninstall SGX Driver"
		 /opt/intel/sgxdriver/uninstall.sh
	fi

	if [[ -d /opt/intel/sgxpsw ]]; then
		  echo "Uninstall SGX PSW"
		  service aesmd stop
		  /opt/intel/sgxpsw/uninstall.sh
	fi

	if [[ -d /opt/intel/sgxsdx ]]; then
		  echo "Uninstall SGX SDX"
		  /opt/intel/sgxsdx/uninstall.sh
	fi

}
compile_linux_sgx_ssl()
{
	rm -rf $GIT_CLONE_PATH/intel-sgx-ssl
	git clone https://github.com/intel/intel-sgx-ssl.git $GIT_CLONE_PATH/intel-sgx-ssl
	if [[ $? -ne 0 ]]; then
		echo "Cloning SGX sgx ssl is failed\n"
		exit -1;
	fi
	pushd $GIT_CLONE_PATH/intel-sgx-ssl
	cd openssl_source
	wget $OPENSSL_URL
	cd ..
	cd Linux
	source /opt/intel/sgxsdk/environment
	make all
	make install
	popd
}

download_and_install_sgx_core()
{
	mkdir -p $GIT_CLONE_PATH
	pushd $GIT_CLONE_PATH
	yum install wget -y
	wget --no-verbose --no-parent --recursive --level=1 --no-directories $SGX_DOWNLOAD_URL 
	chmod 777 sgx_linux_x64*
	./sgx_linux_x64_driver_*.bin
	./sgx_linux_x64_sdk_*.bin
	source /opt/intel/sgxsdk/environment
	./sgx_linux_x64_psw_*.bin
	popd
}

core_sgx_setup()
{
	uninstall_sgx 
	download_and_install_sgx_core
	compile_linux_sgx_ssl
}

setup_sgx_toolkit()
{
	yum install autotools-latest -y
	mkdir -p $SGX_TOOLKIT_INSTALL_PREFIX
	rm -rf $GIT_CLONE_PATH/distributed_hsm-sgxtoolkit
	git clone ssh://git-amr-1.devtools.intel.com:29418/distributed_hsm-sgxtoolkit $GIT_CLONE_PATH/distributed_hsm-sgxtoolkit
	pushd  $GIT_CLONE_PATH/distributed_hsm-sgxtoolkit
	git checkout v3+next-major
	sh autogen.sh
	./configure --prefix=$SGX_TOOLKIT_INSTALL_PREFIX
	make install
	popd
}


core_sgx_setup 
setup_sgx_toolkit 
rm -rf $GIT_CLONE_PATH


#please give installation directory to /opt/intel
