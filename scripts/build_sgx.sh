#!/bin/bash

SGX_VERSION=2.6
SYSLIB_PATH=/usr/lib64
KERNEL_DRIVER="kernel-devel-uname-r == $(uname -r)"
SGX_SDX_CLONE_PATH="https://github.com/intel/linux-sgx.git"
SGX_TOOLKIT_BRANCH="v4+next-major"
SGX_TOOLKIT_URL="ssh://git-amr-1.devtools.intel.com:29418/distributed_hsm-sgxtoolkit"
SGX_TOOLKIT_INSTALL_PREFIX="/opt/intel/sgxtoolkit"
GIT_CLONE_PATH=/tmp/sgxstuff
SGX_DRIVER_VERSION=1.12
CMAKE_EXPECTED_VERSION=3.13
NODE_JS_VERSION=10.16.0
GCC_REQUIRED_VERSION=7
NODE_JS_URL="https://nodejs.org/dist/v$NODE_JS_VERSION/node-v$NODE_JS_VERSION-linux-x64.tar.xz"
SGX_TOOLKIT_WITH_DCAP=1
OP="$1"

if [ -z "$1" ]; then
	echo "No option provided"
	OP="install"
fi

uninstall_sgx()
{
	if [[ -d /opt/intel/sgxsdk ]]; then
		echo "Uninstall SGX SDX"
		/opt/intel/sgxsdk/uninstall.sh
	fi

	if [[ -d /opt/intel/sgxpsw ]]; then
		echo "Uninstall SGX PSW"
		service aesmd stop
		/opt/intel/sgxpsw/uninstall.sh
		rm -rf  /opt/intel/sgxpsw/
	fi

	if [[ -d /opt/intel/sgxssl ]]; then
		echo "Uninstall SGX SSL"
		rm -rf /opt/intel/sgxssl
	fi

	if [[ -d $SGX_TOOLKIT_INSTALL_PREFIX ]]; then
		echo "Uninstall SGX Toolkit"
		rm -rf $SGX_TOOLKIT_INSTALL_PREFIX
		rm -rf /opt/intel/cryptoapitoolkit/
	fi

	if [[ -d $GIT_CLONE_PATH ]]; then
		rm -rf $GIT_CLONE_PATH
	fi

	modinfo intel_sgx
	if [ $? -eq 0 ]; then
		echo "Removing intel_sgx driver"
		modprobe -r intel_sgx
		dkms remove -m sgx -v $SGX_DRIVER_VERSION --all
	else
		echo "intel_sgx module not installed"
	fi

	if [ -d /usr/src/sgx-$SGX_DRIVER_VERSION ]; then
		rm -rf /usr/src/sgx-$SGX_DRIVER_VERSION/
	fi
	find $SYSLIB_PATH -name 'libsgx_*' -o -name 'libdcap_quoteprov.so*' -o -name 'libQuoteVerification.so' -exec rm -rf {} \;
}

compile_linux_sgx_ssl()
{
	source /opt/intel/sgxsdk/environment
	pushd $GIT_CLONE_PATH/linux-sgx/external/sgxssl
	./prepare_sgxssl.sh
	cd Linux
	make install || exit 1
	popd #linux-sgx/external/sgxssl
}

download_and_install_pccs_server()
{
	mkdir -p $GIT_CLONE_PATH
	pushd $GIT_CLONE_PATH

	if [ ! -d $GIT_CLONE_PATH/linux-sgx ]; then
		git clone $SGX_SDX_CLONE_PATH
	fi
	pushd linux-sgx

	# checkout external/dcap_source
	git submodule init
	git submodule update

	yum install epel-release npm -y

	cp -p external/dcap_source/QuoteGeneration/qcnl/linux/sgx_default_qcnl.conf /etc
	sed -i "s/USE_SECURE_CERT=.*/USE_SECURE_CERT=FALSE/g" /etc/sgx_default_qcnl.conf

	pushd external/dcap_source/QuoteGeneration/pccs
	sed -i  "6i\\\tproxy: 'http://proxy-us.intel.com:911'," pckclient.js
	# download and install pre-built nodejs in /usr/local
	wget $NODE_JS_URL
	tar xvf node-v*.tar.xz --strip-components=1 -C /usr/local/
	rm -rf node-v*.tar.xz

	npm config set http-proxy http://proxy-us.intel.com:911/
	npm config set https-proxy http://proxy-us.intel.com:911/
	openssl genrsa 2048 > private.pem
	openssl req -new -key private.pem -out csr.pem -subj "/CN=localhost"
	openssl x509 -req -days 365 -in csr.pem -signkey private.pem -out file.crt
printf "{
\"HTTPS_PORT\": 8081,
\"hosts\": \"0.0.0.0\",
\"uri\": \"https://sbx.api.trustedservices.intel.com/sgx/certification/v1/\",
\"ApiKey\": \"9e0153b3f0c948d9ade866635f039e1e\",
\"RefreshSchedule\": \"0 0 1 * * *\",
\"CacheDB\": \"pckcache.db\",
\"AdminToken\": \"\"
}" > config.json

	./uninstall.sh
	./install.sh
	popd #external/dcap_source/QuoteGeneration/pccs
	
	popd #linux-sgx
	popd #GIT_CLONE_PATH
}

download_and_install_sgx_components()
{
	mkdir -p $GIT_CLONE_PATH
	pushd $GIT_CLONE_PATH

	gcc_version_check

	git clone $SGX_SDX_CLONE_PATH
	pushd linux-sgx

	# checkout external/dcap_source	
	git submodule init
	git submodule update

	yum install epel-release automake autoconf libtool ocaml ocaml-ocamlbuild unzip wget python openssl-devel libcurl-devel protobuf-devel cmake cmake3 zip dkms llvm-toolset-7-cmake llvm-toolset-7 -y

	# DCAP driver build and installation
	pushd external/dcap_source/driver/linux
	yum install "kernel-devel-uname-r == $(uname -r)" -y
	mkdir -p /usr/src/sgx-$SGX_DRIVER_VERSION/
	cp -rpf * /usr/src/sgx-$SGX_DRIVER_VERSION/

	dkms add -m sgx -v $SGX_DRIVER_VERSION
	dkms build -m sgx -v $SGX_DRIVER_VERSION
	dkms install -m sgx -v $SGX_DRIVER_VERSION
	modprobe intel_sgx

	popd #external/dcap_source/driver/linux

	# build SGX SDK and PSW
	./download_prebuilt.sh

	# SGX SDK and PSW compilation
	make || exit 1
	make sdk_install_pkg
	make psw_install_pkg

	#installation
	pushd linux/installer/bin/
	chmod 777 *.bin
	./sgx_linux_x64_psw_*.bin
	./sgx_linux_x64_sdk_*.bin
	source /opt/intel/sgxsdk/environment
	popd #linux/installer/bin/

	pushd external/dcap_source/
	pushd QuoteGeneration

	./download_prebuilt.sh
	# On CentOS, QuoteGeneration make does not work as it tries to build debian package
	make pkg || exit 1
	popd #QuoteGeneration
	
	cp -p QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h QuoteVerification/Src/AttestationLibrary/include/SgxEcdsaAttestation/QuoteVerification.h QuoteGeneration/pce_wrapper/inc/sgx_pce.h QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h QuoteGeneration/quote_wrapper/ql/inc/sgx_dcap_ql_wrapper.h /opt/intel/sgxsdk/include/

	cp -p QuoteGeneration/build/linux/*.so $SYSLIB_PATH
	cp -p QuoteGeneration/psw/ae/data/prebuilt/*.so $SYSLIB_PATH
	ln -fs $SYSLIB_PATH/libsgx_dcap_ql.so $SYSLIB_PATH/libsgx_dcap_ql.so.1
	ln -fs $SYSLIB_PATH/libsgx_default_qcnl_wrapper.so $SYSLIB_PATH/libsgx_default_qcnl_wrapper.so.1
	ln -fs $SYSLIB_PATH/libdcap_quoteprov.so $SYSLIB_PATH/libdcap_quoteprov.so.1

	pushd QuoteVerification/Src
	CMAKE_ACTUAL_VERSION=$(cmake --version | sed "s/\(cmake\|cmake3\) version \([0-9]\.[0-9]\+\).*/\2/" | head -n1)
	RESULT=$(echo "$CMAKE_ACTUAL_VERSION != $CMAKE_EXPECTED_VERSION" | bc -l)
	if [ $RESULT -eq 1 ]; then
		#Cmake3 version 3.13 required for QuoteVerification library to commpile with error so moving system installed cmake 3.6 to llvm-toolset cmake
		mv /opt/rh/llvm-toolset-7/root/usr/bin/cmake /opt/rh/llvm-toolset-7/root/usr/bin/cmake_bck
		ln -s /usr/bin/cmake3 /opt/rh/llvm-toolset-7/root/usr/bin/cmake
		echo "		copying cmake3 version"
	fi
	sed -i 's/^BUILD_TESTS=ON$/BUILD_TESTS=OFF/g' release
	./release || exit 1
	popd #QuoteVerification/Src
	cp -p QuoteVerification/Src/Build/Release/dist/lib/libQuoteVerification.so $SYSLIB_PATH
	popd #external/dcap_source/

	popd #linux-sgx
	popd #$SGX_SDX_CLONE_PATH
}

core_sgx_setup()
{
	uninstall_sgx
	download_and_install_sgx_components
	compile_linux_sgx_ssl
}

gcc_version_check()
{
	yum install bc -y
	rpm -q gcc
	if [ $? -ne 0 ]; then
		"GCC Package not found, please install the following: yum install gcc-c++ git kernel-headers autotools-latest kernel-devel $KERNEL_DRIVER"
		exit 0
	fi

	GCC_ACTUAL_VERSION=$(gcc -dumpversion | sed "s/\([0-9]\).*/\1/")
	RESULT=$(echo "$GCC_ACTUAL_VERSION >= $GCC_REQUIRED_VERSION" | bc -l)
	echo "$GCC_ACTUAL_VERSION, $cmd, $result"

	if [ $RESULT -eq 0 ]; then
	     	echo "Expected GCC version: $GCC_REQUIRED_VERSION does not matched with actual $GCC_ACTUAL_VERSION"
		echo  -e "Please run following command\nyum install centos-release-scl scl-utils devtoolset-7-gcc-c++ llvm-toolset-7-cmake llvm-toolset-7 -y\n"
		echo -e "scl enable devtoolset-7 llvm-toolset-7 \"/bin/sh scripts/build_sgx.sh\""
		exit -1
	fi
	echo "Required GCC version Found"
}

setup_sgx_toolkit()
{
	mkdir -p $SGX_TOOLKIT_INSTALL_PREFIX
	rm -rf $GIT_CLONE_PATH/distributed_hsm-sgxtoolkit

	git clone $SGX_TOOLKIT_URL $GIT_CLONE_PATH/distributed_hsm-sgxtoolkit
	pushd  $GIT_CLONE_PATH/distributed_hsm-sgxtoolkit
	git checkout $SGX_TOOLKIT_BRANCH
	bash autogen.sh

	if [ $SGX_TOOLKIT_WITH_DCAP ]; then
	./configure --prefix=$SGX_TOOLKIT_INSTALL_PREFIX --with-dcap-path=$GIT_CLONE_PATH/linux-sgx/external/dcap_source
	else
	./configure --prefix=$SGX_TOOLKIT_INSTALL_PREFIX
	fi
	make install || exit 1
	popd
}

if [[ "$OP" = *"uninstall"* ]]; then
	echo "Uninstall SGX commponents"
	uninstall_sgx
elif [[ "$OP" = *"install" ]]; then
	echo "Install SGX components (Driver, SDK, PSW)"
	yum install gcc-c++ git kernel-headers autotools-latest kernel-devel -y
	core_sgx_setup
	setup_sgx_toolkit
elif [[ "$OP" = *"install-pccs-server"* ]]; then
	echo "Install SGX PCCS server"
	download_and_install_pccs_server
elif [[ "$OP" = *"install-sgxtoolkit"* ]]; then
	setup_sgx_toolkit
else
	"Command: invalid command"
fi

#please provide /opt/intel as installation path for SDK
