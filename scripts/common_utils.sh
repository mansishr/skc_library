#!/bin/bash
##=====================================================================================================================
##COMMON_CONSTANT
##=====================================================================================================================

readonly FLAG_ENABLE=1
readonly FLAG_DISABLE=0

readonly EXEC_RULE_ABORT=1
readonly EXEC_RULE_WARN=2

readonly CODE_EXEC_SUCCESS=0
readonly CODE_PARSE_ERROR=1
readonly CODE_INPUT_ERROR=2
readonly CODE_IO_FAILURE=3
readonly CODE_EXEC_ERROR=4
readonly CODE_EXEC_WARN=5
readonly CODE_OPENSSL_ERROR=6
readonly CODE_CONCURRENCY_ERROR=7
readonly CODE_CONFIG_ERROR=8
readonly CODE_OS_ERROR=9
readonly CODE_DEPS_ERROR=10

#=====================================================================================================================
#LOGGING_CONSTANT
#=====================================================================================================================

readonly CODE_ERROR='\033[0;31m' #RED_COLOR
readonly CODE_OK='\033[0;32m'  #GREEN_COLOR
readonly CODE_WARNING='\033[0;33m' #BROWN/ORANGE_COLOR   
readonly CODE_NC='\033[0m' #NO_COLOR`


declare -a LOG_PREFIX=("${CODE_OK}INFO:" "${CODE_ERROR}ERROR:" "${CODE_WARNING}WARN:"  "${CODE_OK}DEBUG:")
declare -a LOG_SUFFIX=(" successful${CODE_NC}" " failed!${CODE_NC}" " not successful !${CODE_NC}"  ".${CODE_NC}")

readonly LOG_OK=0
readonly LOG_ERROR=1
readonly LOG_WARN=2
readonly LOG_DEBUG=3

#DEFAULT_LOGGING
declare FLAG_VERBOSE=$FLAG_DISABLE
declare LOG_FILE=""
#=====================================================================================================================
#VARIABLES
declare SELF_PID=$$
declare EXIT_STAT_FILE=$(mktemp)
declare LOG_PREFIX=""


to_stderr(){
	(>&2 $*)
}


log_msg()
{
	local log_level=$1
	local log_msg=$2
	#if [ $FLAG_VERBOSE -eq $FLAG_ENABLE ] || [ $log_level -eq $LOG_ERROR ]; then
	if [ $FLAG_VERBOSE -eq $FLAG_ENABLE ]; then
		$(to_stderr echo -e "${LOG_PREFIX[$log_level]} ${log_msg} ${LOG_SUFFIX[$log_level]}") 
		if [ ! -z "$LOG_FILE" ] && [ -f $LOG_FILE ]; then
			echo -e "${LOGGING_PREFIX} [$(date +'%Y-%m-%d %H:%M:%S')]\$ ${LOG_PREFIX[$log_level]} ${log_msg} ${LOG_SUFFIX[$log_level]}" >> "$LOG_FILE"
			#echo -e "$LOG_FILE"
		fi
	fi
}
get_log()
{
	echo $FLAG_VERBOSE
}

set_log()
{
	FLAG_VERBOSE=$1
	LOGGING_PREFIX=$2
}
set_log_file()
{
	if [ ! -z "$1" -a "$1" != " " ]; then
	    LOG_FILE=$1
		touch $LOG_FILE
		chmod 755 $LOG_FILE
		log_msg $LOG_DEBUG "LOG_FILE:$LOG_FILE"
	fi
}

send_status()
{
  #log_msg $LOG_DEBUG "Caught Signal ..."
  local exit_val=$(cat $EXIT_STAT_FILE)
  rm -rf $EXIT_STAT_FILE
  exit $exit_val
}

exit_script()
{
	local log_level=$1
	local log_msg="$2"
	local exit_code=$3
	log_msg $log_level "$log_msg"
	if [ $log_level -eq $LOG_ERROR ] || [ $log_level -eq $LOG_WARN ]; then
		echo $exit_code > $EXIT_STAT_FILE
		kill -9 $SELF_PID
	elif [[ $1 -eq $LOG_OK ]]; then
		exit $CODE_EXEC_SUCCESS
	fi
}

get_last_cmd_exec_status()
{
	local last_exec_stat=$?
	return $last_exec_stat
}

exec_linux_cmd()
{
	local exec_cmd="$1"
	local exec_rule=$2
	local log_msg="$3"
	local exit_code=$4

	eval "$exec_cmd"
	last_exec_stat=$?

	if [ $last_exec_stat -ne 0 ] && [ $exec_rule -eq $EXEC_RULE_ABORT ]; then
		exit_script $LOG_ERROR "$log_msg" $exit_code
	elif [ $last_exec_stat -ne 0 ] && [ $exec_rule -eq $EXEC_RULE_WARN ]; then
		$(log_msg $LOG_WARN "$log_msg")
	else
		$(log_msg $LOG_DEBUG "$LOG_MSG : CMD:$exec_cmd")
	fi
}

lock() {
	local lock_fd=$1
	local file_name=$2

	eval "exec $lock_fd>/var/lock/.${file_name}_lock"
    flock -n $lock_fd \
        && return 0 \
        || return 1
}

update_agent_config()
{
	local cs_ip=$1
	local token=$2
	local agent_conf=$3
	sed -i "s/\(server\=\"\)\(.*\)\(\"\)/\1$cs_ip\3/g" $agent_conf
	sed -i "s/\(token\=\"\)\(.*\)\(\"\)/\1$token\3/g" $agent_conf
}

check_proxy()
{
	if [[ (-z "${http_proxy}")||(-z "${https_proxy}") ]];
	then
		log_msg $LOG_ERROR "HTTP Proxies not set. If you are running this installer behind a proxy, please set up http_proxy and https_proxy environment variables before installation."
		return $CODE_CONFIG_ERROR
	else
		log_msg $LOG_DEBUG "HTTP Proxies for http and https set. Continuing installation....."
		return $CODE_EXEC_SUCCESS
	fi
}

check_linux_version()
{
        local OS=$(cat /etc/*release | grep ^NAME | cut -d'"' -f2)
        local VER=$(cat /etc/*release | grep ^VERSION_ID | tr -d 'VERSION_ID="')
				
		local os_arr_size=`expr ${#SKC_COMPONENT_INSTALL_OS[*]} - 1`;
        local ver_arr_size=`expr ${#SKC_COMPONENT_INSTALL_OS_VER[*]} - 1`;

        log_msg $LOG_DEBUG "OS Array Size:${os_arr_size}, Ver Array Size:${ver_arr_size}"

        if [ ${os_arr_size} -ne ${ver_arr_size} ]; then
                log_msg $LOG_ERROR "OS distribution ${OS} version ${VER} Array data\n"
                return $CODE_OS_ERROR
        fi

        for i in $(seq 0 ${os_arr_size}); do
                PARAM_OS="${SKC_COMPONENT_INSTALL_OS[$i]}";
                PARAM_VER="${SKC_COMPONENT_INSTALL_OS_VER[$i]}";
				#log_msg $LOG_DEBUG "Input OS distribution ${OS}:${PARAM_OS} version ${VER}:${PARAM_VER}"
		
        if [[ "${OS}" = "${PARAM_OS}" ]]; then
			#Compare OS versions: CentOS version should be 7 or later, RHEL version should be 7.5 or later
			compare_os_version=`echo "$VER >= $PARAM_VER" | bc`
			if [ $compare_os_version ]; then
				log_msg $LOG_DEBUG "OS distribution ${OS} version ${VER} matched"
				return $CODE_EXEC_SUCCESS
			else
				log_msg $LOG_WARN "Error: OS distribution ${OS} version ${VER} NOT Correct!\n"
				continue;
			fi
    	else
            log_msg $LOG_WARN "OS distribution -${OS}:${PARAM_OS}- Not Supported\n"
            continue;
    	fi

    	done
		
		return $CODE_OS_ERROR
}
 
CheckWhetherProcessRunning()
{
	local process_name="$1"
	if pgrep -x "$process_name" > /dev/null
	then
		return $CODE_EXEC_SUCCESS
	else
		return $CODE_EXEC_ERROR
	fi
}


download_deps()
{
	pushd "$PWD"
	cd "$1"

	git_var=`echo "$(git version)" | sed -e "s/git version \([0-9]\.[0-9]\).*/\1/"`;
	log_msg $LOG_DEBUG "Sub module init started"
	$(exec_linux_cmd "git submodule init" $EXEC_RULE_ABORT "Submodule init" $CODE_EXEC_ERROR)
	log_msg $LOG_DEBUG "Sub module init completed"

	if [[ "$git_var" = "1.8" ]]; then
		log_msg $LOG_DEBUG "Sub module update started"
		$(exec_linux_cmd "git submodule update --init --recursive --remote" $EXEC_RULE_ABORT 'Submodule update' $CODE_EXEC_ERROR)
		log_msg $LOG_DEBUG "Sub module update completed"
	elif [[ "$git_var" = "1.7" ]]; then 
		log_msg $LOG_DEBUG "Sub module update started"
		$(exec_linux_cmd "git submodule update --init --recursive" $EXEC_RULE_ABORT 'Submodule update' $CODE_EXEC_ERROR)
		log_msg $LOG_DEBUG "Sub module update completed"
	fi
	popd 
}

download_external_components()
{
    EXT_DIR=$1
    echo "External DIR=$EXT_DIR"
    $(exec_linux_cmd "rm -rf $EXT_DIR" $EXEC_RULE_ABORT "Creating directory $1" $CODE_EXEC_SUCCESS)
    $(exec_linux_cmd "mkdir -p $EXT_DIR" $EXEC_RULE_ABORT "Creating directory $1" $CODE_EXEC_SUCCESS)
    download_external_openssl $EXT_DIR
    download_external_libcurl $EXT_DIR
    if [[ "$SKC_SGX_SUPPORT" = "$TRUE" ]]; then
        download_external_SKC_SGXSDK $EXT_DIR
        download_external_SKC_SGXSSL $EXT_DIR
    fi
}

download_external_openssl()
{
    pushd "$PWD"
    cd "$1"
    $(exec_linux_cmd "wget https://www.openssl.org/source/$SKC_COMPONENT_EXT_OPENSSL_VERSION.tar.gz" $EXEC_RULE_ABORT "Downloading openssl version $SKC_COMPONENT_EXT_OPENSSL_VERSION" $CODE_EXEC_SUCCESS)
    $(exec_linux_cmd "tar xvzf $SKC_COMPONENT_EXT_OPENSSL_VERSION.tar.gz" $EXEC_RULE_ABORT "Untar openssl version $SKC_COMPONENT_EXT_OPENSSL_VERSION" $CODE_EXEC_SUCCESS)
    popd
}

download_external_libcurl()
{
    pushd "$PWD"
    cd "$1"
    $(exec_linux_cmd "git clone -b $SKC_COMPONENT_EXT_LIBCURL_VERSION https://github.com/curl/curl.git" $EXEC_RULE_ABORT "Cloning libcurl version $SKC_COMPONENT_EXT_LIBCURL_VERSION to $1" $CODE_EXEC_SUCCESS)
    popd
}

download_external_SKC_SGXSDK()
{
    pushd "$PWD"
    cd "$1"
    $(exec_linux_cmd "wget https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/rhel8.0-server/$SKC_SGX_SDK_BIN_VERSION" $EXEC_RULE_ABORT "Downloading $SKC_SGX_SDK_BIN_VERSION to $1" $CODE_EXEC_SUCCESS)
    chmod 755 $SKC_SGX_SDK_BIN_VERSION
    popd
}

download_external_SKC_SGXSSL()
{
    pushd "$PWD"
    cd "$1"
    $(exec_linux_cmd "git clone -b $SKC_SGX_SSL_VERSION https://github.com/intel/intel-sgx-ssl.git sgx-ssl" $EXEC_RULE_ABORT 'Cloning intel-sgx-ssl' $CODE_EXEC_SUCCESS)
    cp $SKC_COMPONENT_EXT_OPENSSL_VERSION.tar.gz sgx-ssl/openssl_source/
    popd
}

SKC_COMPONENT_OS_PAC_INSTALLERtall_external_components()
{
    install_external_openssl $1
    install_external_libcurl $1
    if [[ "$SKC_SGX_SUPPORT" = "$TRUE" ]]; then
        install_external_SKC_SGXSDK  $1
        install_external_SKC_SGXSSL  $1
    fi
}

install_external_openssl()
{
    pushd "$PWD"
    cd "$1/$SKC_COMPONENT_EXT_OPENSSL_VERSION/"
    $(exec_linux_cmd "./config -d --prefix=$SKC_COMPONENT_EXT_OPENSSL_INSTALL_DIR" $EXEC_RULE_ABORT "Configuring OpenSSL into $SKC_COMPONENT_EXT_OPENSSL_INSTALL_DIR" $CODE_EXEC_SUCCESS)
    $(exec_linux_cmd "make" $EXEC_RULE_ABORT "Compiling OpenSSL" $CODE_EXEC_SUCCESS)
    $(exec_linux_cmd "make install" $EXEC_RULE_ABORT "Installing OpenSSL" $CODE_EXEC_SUCCESS)
    popd
}

install_external_libcurl()
{
    pushd "$PWD"
    cd "$1/curl"
    $(exec_linux_cmd "./buildconf" $EXEC_RULE_ABORT "Building configuration files" $CODE_EXEC_SUCCESS)
    $(exec_linux_cmd "./configure --prefix=$SKC_COMPONENT_EXT_LIBCURL_INSTALL_DIR --with-ssl=$SKC_COMPONENT_EXT_OPENSSL_INSTALL_DIR" $EXEC_RULE_ABORT "Configuring libcurl into $(SKC_COMPONENT_EXT_LIBCURL_INSTALL_DIR)" $CODE_EXEC_SUCCESS)
    $(exec_linux_cmd "make" $EXEC_RULE_ABORT "Compiling OpenSSL" $CODE_EXEC_SUCCESS)
    $(exec_linux_cmd "make install" $EXEC_RULE_ABORT "Installing libcurl" $CODE_EXEC_SUCCESS)
    popd
}

install_external_SKC_SGXSDK()
{
    pushd "$PWD"
    cd "$1"
    $(exec_linux_cmd "printf 'no\n$SKC_SGX_SDK_INSTALL_PATH\n' | ./$SKC_SGX_SDK_BIN_VERSION" $EXEC_RULE_ABORT "Installing SKC_SGX SDK" $CODE_EXEC_SUCCESS)
    popd
}

install_external_SKC_SGXSSL()
{
    pushd "$PWD"
    cd "$1/sgx-ssl/Linux"
    source /opt/intel/sgxsdk/environment
    $(exec_linux_cmd "make all" "Building SKC_SGX SSL" $CODE_EXEC_SUCCESS)
    $(exec_linux_cmd "make install" "Installing SKC_SGX SSL" $CODE_EXEC_SUCCESS)
    popd
}


check_pre_condition()
{
    PROXY_REQUIRED=$1

    if [ $PROXY_REQUIRED -eq $FLAG_ENABLE ]; then
        $(check_proxy)
        if [ $? -ne $CODE_EXEC_SUCCESS ]; then
            log_msg $LOG_ERROR "Proxy"
            return $CODE_EXEC_ERROR
        fi
    fi

    $(check_linux_version)
    if [ $? -ne $CODE_EXEC_SUCCESS ]; then
        log_msg $LOG_ERROR "Invalid Enviromnent"
        return $CODE_EXEC_ERROR
    fi
}

install_pre_requisites()
{
	local PRE_REQUISITES="none"

	if [ -z "$1" ]; then
		PRE_REQUISITES="all"
	else
		PRE_REQUISITES="$1"
	fi

	if [ $PROXY_REQUIRED -eq $TRUE ]; then 
		check_proxy
		if [ $? -ne 0 ]; then 
			exit_script $LOG_ERROR "Invalid Proxy" $CODE_EXEC_ERROR
		fi
	fi

	$SKC_COMPONENT_OS_PAC_INSTALLER localinstall -y https://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/libgda-5.2.8-4.fc30.x86_64.rpm
	$SKC_COMPONENT_OS_PAC_INSTALLER localinstall -y https://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/libgda-devel-5.2.8-4.fc30.x86_64.rpm
	$SKC_COMPONENT_OS_PAC_INSTALLER localinstall -y https://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/libgda-sqlite-5.2.8-4.fc30.x86_64.rpm
	$SKC_COMPONENT_OS_PAC_INSTALLER localinstall  -y https://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/o/openssl-pkcs11-0.4.10-1.fc30.x86_64.rpm
	$SKC_COMPONENT_OS_PAC_INSTALLER localinstall -y https://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/libp11-devel-0.4.10-1.fc30.x86_64.rpm

	if [ "${PRE_REQUISITES}" = "dev" ]; then
	   $SKC_COMPONENT_OS_PAC_INSTALLER update -y && $SKC_COMPONENT_OS_PAC_INSTALLER install ${SKC_COMPONENT_DEV_PRE_REQUISITES} -y
	elif  [ "${PRE_REQUISITES}" = "devOps" ]; then 
	   $SKC_COMPONENT_OS_PAC_INSTALLER groupinstall -y "Development Tools"
	elif [ "${PRE_REQUISITES}" = "all" ]; then
	   $SKC_COMPONENT_OS_PAC_INSTALLER update -y && $SKC_COMPONENT_OS_PAC_INSTALLER groupinstall "Development Tools" -y && $SKC_COMPONENT_OS_PAC_INSTALLER install ${SKC_COMPONENT_DEV_PRE_REQUISITES} -y
	fi

	if [ $? -ne 0 ]; then
		exit_script $LOG_ERROR "Pre-Requisites installation" $CODE_EXEC_ERROR
	fi
	log_msg $LOG_DEBUG "Pre-Requisites installation" 

}

set_permission_and_grp()
{
	groupadd ${SKC_COMPONENT_GRP}
	if [ $? -eq 0 ] || [ $? -eq 9 ]; then
		exit_script $LOG_ERROR "Group ${SKC_COMPONENT_GRP} add" $CODE_EXEC_ERROR
	fi 

	if [ ! -d ${SKC_COMPONENT_INSTALL_DIR} ]; then
		exit_script $LOG_ERROR "Group ${SKC_COMPONENT_GRP} add configuration failed" $CODE_EXEC_ERROR
	fi
	chgrp -hR ${SKC_COMPONENT_GRP} ${SKC_COMPONENT_INSTALL_DIR} 
	chmod ${SKC_COMPONENT_GRP_PERMISSION} ${SKC_COMPONENT_INSTALL_DIR}
	chmod +t ${SKC_COMPONENT_INSTALL_DIR}
}

get_file_count()
{
	local cnt=$(find / -name "$1" | wc -l)
	log_msg $LOG_DEBUG "File: $1 total $file count: $cnt" 
	echo $cnt
}

compile_safestring()
{

	echo $PATH
	mkdir -p $PWD/safestringlib/obj
	mkdir -p $PWD/safestringlib/objtest
	$(exec_linux_cmd "make clean -C ./safestringlib" $EXEC_RULE_ABORT "Make" $CODE_EXEC_ERROR)
	$(exec_linux_cmd "make -C ./safestringlib" $EXEC_RULE_ABORT "Make" $CODE_EXEC_ERROR)
	log_msg $LOG_DEBUG "Safestring  lib: Compilation completed"
}

# Extract version of the dependency packages installed
fetch_installed_dependency_packages_version()
{
	in="$1"
	out="$2"
	
	log_msg $LOG_DEBUG "Dependency Packages: $in"
	log_msg $LOG_DEBUG "Dependency Packages Version: $out"
	
	grep "^" "$in" | xargs rpm -q | tee "$out"
}
