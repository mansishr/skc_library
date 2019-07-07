#!/bin/bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
OS=$(cat /etc/os-release | grep '^NAME=.*$' | sed -e 's/^NAME="\(.*\)"/\1/')

if [[ "$OS" = *"CentOS"* ]]; then
        echo "1.$OS"
        SGX_DOWNLOAD_URL="https://download.01.org/intel-sgx/linux-2.5/centos7.5-server/"
elif [[ "$OS" = *"Red Hat"* ]]; then
        echo "2.$OS"
        SGX_DOWNLOAD_URL="https://download.01.org/intel-sgx/linux-2.5/rhel7.4-server/"
else
        echo "No match: 3.$OS for SGX Installation"
	exit -1
fi

OPENSSL_URL="https://www.openssl.org/source/openssl-1.1.1a.tar.gz"
SGX_SDX_CLONE_PATH="https://github.com/intel/linux-sgx.git"
SGX_TOOLKIT_BRANCH="v4+next-major"
SGX_TOOLKIT_URL="ssh://git-amr-1.devtools.intel.com:29418/distributed_hsm-sgxtoolkit"
SGX_TOOLKIT_INSTALL_PREFIX="/opt/intel/sgxtoolkit"
GIT_CLONE_PATH=/tmp/sgxstuff
SGX_DRIVIER="new"
KERNEL_DRIVER="kernel-devel-uname-r == $(uname -r) -y"
CMAKE_EXPECTED_VERSION=3.13
GCC_REQUIRED_VERSION=7
DCAP_SUPPORT=true
OP="$1"

if [ -z "$1" ]; then
	echo "No option provided"
	OP="install"
fi 


uninstall_sgx()
{
	if [[ "${SGX_DRIVIER}" = *"new"* ]]; then

		if [ -d /opt/intel/sgxdriver ]; then
			echo "Uninstall SGX Driver"
			 /opt/intel/sgxdriver/uninstall.sh
		fi

		/sbin/modprobe -r intel_sgx
		dkms remove -m sgx -v 0.10 --all

		if [ -d /usr/src/sgx-0.10 ]; then
			rm -rf /usr/src/sgx-0.10/
		fi
	elif [[ "${SGX_DRIVIER}" = *"old"* ]]; then
		if [ -d /opt/intel/sgxdriver ]; then
			echo "Uninstall SGX Driver"
			 /opt/intel/sgxdriver/uninstall.sh
		fi
	fi


	if [[ -d /opt/intel/sgxpsw ]]; then
		  echo "Uninstall SGX PSW"
		  service aesmd stop
		  /opt/intel/sgxpsw/uninstall.sh
	fi

	if [[ -d /opt/intel/sgxsdk ]]; then
		  echo "Uninstall SGX SDX"
		  /opt/intel/sgxsdk/uninstall.sh
	fi
	if [[ -d $SGX_TOOLKIT_INSTALL_PREFIX ]]; then
		  echo "Uninstall SGX Toolkit"
		  rm -rf $SGX_TOOLKIT_INSTALL_PREFIX
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

download_and_install_intel_sgx_driver()
{
	mkdir -p $GIT_CLONE_PATH
	pushd $GIT_CLONE_PATH

	gcc_version_check

	git clone $SGX_SDX_CLONE_PATH
	pushd linux-sgx
		git submodule init
		git submodule update

		yum install epel-release automake autoconf libtool ocaml ocaml-ocamlbuild wget python openssl-devel libcurl-devel protobuf-devel cmake cmake3 zip dkms llvm-toolset-7-cmake llvm-toolset-7 -y
		./download_prebuilt.sh
		make

		pushd psw/ae/le
		make
		popd #psw/ae/le


		#compilation
		make sdk_install_pkg
		make psw_install_pkg

		#installation
		pushd linux/installer/bin/ 
		chmod 777 *.bin
		./sgx_linux_x64_sdk_*.bin
		./sgx_linux_x64_psw_*.bin
		popd #linux/installer/bin/ 


		if [ $DCAP_SUPPORT ]; then
			echo "====================================WITH_DCAP_SUPPORT====================================="
			cp $SCRIPT_DIR/*.patch $GIT_CLONE_PATH
			pushd external/dcap_source/
				git apply $GIT_CLONE_PATH/QuoteGeneration.patch	
				git apply $GIT_CLONE_PATH/QuoteVerification.patch

				pushd QuoteGeneration
				./download_prebuilt.sh
				source /opt/intel/sgxsdk/environment
				make pkg
				popd #QuoteGeneration
				
				cp QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h QuoteVerification/Src/AttestationLibrary/include/SgxEcdsaAttestation/QuoteVerification.h   QuoteGeneration/pce_wrapper/inc/sgx_pce.h QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h QuoteGeneration/quote_wrapper/ql/inc/sgx_dcap_ql_wrapper.h   /opt/intel/sgxsdk/include

			
				pushd QuoteGeneration/qcnl/linux
				make 
				popd #QuoteGeneration/qcnl/linux

				pushd QuoteGeneration/qpl/linux
				make 
				popd #QuoteGeneration/qpl/linux
				

				cp QuoteGeneration/build/linux/*.so /lib64/
				cp QuoteGeneration/psw/ae/data/prebuilt/libsgx_qe3.signed.so /lib64/	
				cp $GIT_CLONE_PATH/linux-sgx/psw/ae/data/prebuilt/libsgx_pce.signed.so  /lib64
				chmod au+x /lib64/libsgx_pce.signed.so
				ln -s /lib64/libsgx_default_qcnl_wrapper.so /lib64/libsgx_default_qcnl_wrapper.so.1
				ln -s /lib64/libsgx_dcap_ql.so /lib64/libsgx_dcap.so.1

			
				pushd QuoteVerification/Src 
				CMAKE_ACTUAL_VERSION=$(cmake --version | sed "s/cmake version \([0-9]\.[0-9]\+\).*/\1/" | head -n1)
				RESULT=$(echo "$CMAKE_ACTUAL_VERSION != $CMAKE_EXPECTED_VERSION" | bc -l)
				if [ $RESULT -eq 1 ]; then
					#Cmake3 version 3.13 required for QuoteVerification library to commpile with error so moving system installed cmake 3.6 to llvm-toolset cmake
					mv /opt/rh/llvm-toolset-7/root/usr/bin/cmake /opt/rh/llvm-toolset-7/root/usr/bin/cmake_bck
					ln -s /usr/bin/cmake3 /opt/rh/llvm-toolset-7/root/usr/bin/cmake
				fi
				./release
				popd #QuoteVerification/Src
				cp QuoteVerification/Src/Build/Release/dist/lib/libQuoteVerification.so /lib64/
			popd #external/dcap_source/
		else
			echo "====================================WITHOUT_DCAP_SUPPORT====================================="
		fi

		#new_driver_compilation/installation	
		pushd external/dcap_source/driver/linux

			mkdir -p  /usr/src/sgx-0.10/
			cp -r * /usr/src/sgx-0.10/

			dkms add -m sgx -v 0.10
			dkms build -m sgx -v 0.10
			dkms install -m sgx -v 0.10
			/sbin/modprobe intel_sgx
		popd #external/dcap_source/driver/linux

	
	popd #linux-sgx
	popd #$SGX_SDX_CLONE_PATH

}

download_and_install_isgx_driver()
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
	if [[ "${SGX_DRIVIER}" = *"old"* ]]; then
		download_and_install_isgx_driver
	elif [[ "${SGX_DRIVIER}" = *"new"* ]]; then
		download_and_install_intel_sgx_driver
	else
		echo "invalid input for driver, installing isgx driver"
		download_and_install_isgx_driver
	fi
	compile_linux_sgx_ssl
}

gcc_version_check()
{
	yum install bc -y

	GCC_ACTUAL_VERSION=$(gcc -dumpversion | sed "s/\([0-9]\).*/\1/")
	RESULT=$(echo "$GCC_ACTUAL_VERSION >= $GCC_REQUIRED_VERSION" | bc -l)
	echo "$GCC_ACTUAL_VERSION, $cmd, $result"

	if [ $RESULT -eq 0 ]; then
	     	echo "Expected GCC version: $GCC_REQUIRED_VERSION does not matched with actual $GCC_ACTUAL_VERSION"
		echo  -e "Please do run following command\nyum install centos-release-scl devtoolset-7-gcc-c++ llvm-toolset-7-cmake llvm-toolset-7 llvm-toolset-7 -y\n"
		echo -e "scl enable devtoolset-7 llvm-toolset-7 \"/bin/sh scripts/build_sgx.sh\""
		exit -1
	fi
	echo "Expected GCC version: $GCC_REQUIRED_VERSION does matched with actual $GCC_ACTUAL_VERSION, result=$result"
}

setup_sgx_toolkit()
{
	mkdir -p $SGX_TOOLKIT_INSTALL_PREFIX
	rm -rf $GIT_CLONE_PATH/distributed_hsm-sgxtoolkit

	if [[ "$SGX_TOOLKIT_BRANCH" == *"v4+next-major"* ]]; then
		gcc_version_check
	fi
	git clone $SGX_TOOLKIT_URL $GIT_CLONE_PATH/distributed_hsm-sgxtoolkit
	pushd  $GIT_CLONE_PATH/distributed_hsm-sgxtoolkit
	git checkout $SGX_TOOLKIT_BRANCH
	bash autogen.sh
	if [ $DCAP_SUPPORT ]; then
		./configure --prefix=$SGX_TOOLKIT_INSTALL_PREFIX --with-dcap-path=$GIT_CLONE_PATH/linux-sgx/external/dcap_source
	else
		./configure --prefix=$SGX_TOOLKIT_INSTALL_PREFIX
	fi
	make install
	popd
}


if [[ "$OP" = *"uninstall"* ]]; then
	echo "Uninstall SGX commponents"
	uninstall_sgx 
elif [[ "$OP" = *"install"* ]]; then
	echo "Install SGX commponents"
	yum install gcc-c++ git kernel-headers autotools-latest $KERNEL_DEVEL -y
	core_sgx_setup 
	setup_sgx_toolkit 
	rm -rf $GIT_CLONE_PATH
else
	"Command: invalid command"
fi

#please give installation directory to /opt/intel
