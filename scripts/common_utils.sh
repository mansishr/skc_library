#!/bin/bash

readonly FLAG_ENABLE=1
readonly FLAG_DISABLE=0

readonly EXEC_RULE_ABORT=1
readonly EXEC_RULE_WARN=2

readonly CODE_EXEC_SUCCESS=0
readonly CODE_EXEC_ERROR=1
readonly CODE_CONFIG_ERROR=2
readonly CODE_OS_ERROR=3

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

	$SKC_COMPONENT_OS_PAC_INSTALLER localinstall -y https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/e/epel-release-8-8.el8.noarch.rpm
	$SKC_COMPONENT_OS_PAC_INSTALLER localinstall -y https://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/s/softhsm-2.5.0-3.fc30.1.x86_64.rpm
	$SKC_COMPONENT_OS_PAC_INSTALLER localinstall -y https://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/m/makeself-2.4.0-3.fc30.noarch.rpm
	$SKC_COMPONENT_OS_PAC_INSTALLER localinstall -y https://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/libgda-5.2.8-4.fc30.x86_64.rpm
	$SKC_COMPONENT_OS_PAC_INSTALLER localinstall -y https://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/libgda-devel-5.2.8-4.fc30.x86_64.rpm
	$SKC_COMPONENT_OS_PAC_INSTALLER localinstall -y https://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/libgda-sqlite-5.2.8-4.fc30.x86_64.rpm
	if [ "${PRE_REQUISITES}" = "dev" ]; then
	   $SKC_COMPONENT_OS_PAC_INSTALLER update -y && $SKC_COMPONENT_OS_PAC_INSTALLER install ${SKC_COMPONENT_DEV_PRE_REQUISITES} -y
	elif  [ "${PRE_REQUISITES}" = "devOps" ]; then 
	   $SKC_COMPONENT_OS_PAC_INSTALLER groupinstall -y "Development Tools"
	elif [ "${PRE_REQUISITES}" = "all" ]; then
	   $SKC_COMPONENT_OS_PAC_INSTALLER update -y && $SKC_COMPONENT_OS_PAC_INSTALLER groupinstall "Development Tools" -y && $SKC_COMPONENT_OS_PAC_INSTALLER install ${SKC_COMPONENT_DEV_PRE_REQUISITES} -y
	fi

	git clone https://github.com/OpenSC/libp11.git && cd libp11
	./bootstrap
	./configure --with-enginesdir=/usr/lib64/engines-1.1/
	make install
	cd ..
	rm -rf libp11

	# required for aes_test
	ln -sf /usr/lib64/libjsoncpp.so /usr/lib64/libjsoncpp.so.0

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
