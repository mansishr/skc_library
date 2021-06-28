#!/bin/bash
readonly FLAG_ENABLE=1
readonly FLAG_DISABLE=0
readonly EXEC_RULE_ABORT=1
readonly EXEC_RULE_WARN=2
readonly CODE_EXEC_SUCCESS=0
readonly CODE_EXEC_ERROR=1
readonly CODE_CONFIG_ERROR=2
readonly CODE_OS_ERROR=3
readonly CODE_ERROR='\033[0;31m'
readonly CODE_OK='\033[0;32m'
readonly CODE_WARNING='\033[0;33m'
readonly CODE_NC='\033[0m'
readonly LOG_OK=0
readonly LOG_ERROR=1
readonly LOG_WARN=2
readonly LOG_DEBUG=3

declare FLAG_VERBOSE=$FLAG_DISABLE
declare LOG_FILE=""
declare SELF_PID=$$
declare EXIT_STAT_FILE=$(mktemp)

# Check OS and VERSION
OS=$(cat /etc/os-release | grep ^ID= | cut -d'=' -f2)
temp="${OS%\"}"
temp="${temp#\"}"
OS="$temp"
VER=$(cat /etc/os-release | grep ^VERSION_ID | tr -d 'VERSION_ID="')
OS_FLAVOUR="$OS""$VER"

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
		fi
	fi
}

set_log()
{
	FLAG_VERBOSE=$1
	LOGGING_PREFIX=$2
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

check_linux_version()
{
	local OS=$(cat /etc/*release | grep ^NAME | cut -d'"' -f2)
	local VER=$(cat /etc/*release | grep ^VERSION_ID | tr -d 'VERSION_ID="')
				
	local os_arr_size=`expr ${#SKCLIB_INSTALL_OS[*]} - 1`;
	local ver_arr_size=`expr ${#SKCLIB_INSTALL_OS_VER[*]} - 1`;

	if [ ${os_arr_size} -ne ${ver_arr_size} ]; then
		log_msg $LOG_ERROR "OS distribution ${OS} version ${VER} Array data\n"
		return $CODE_OS_ERROR
	fi

	for i in $(seq 0 ${os_arr_size}); do
		PARAM_OS="${SKCLIB_INSTALL_OS[$i]}";
		PARAM_VER="${SKCLIB_INSTALL_OS_VER[$i]}";
		
		if [[ "${OS}" = "${PARAM_OS}" ]]; then
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
 
check_pre_condition()
{
	$(check_linux_version)
	if [ $? -ne $CODE_EXEC_SUCCESS ]; then
		log_msg $LOG_ERROR "Invalid Enviromnent"
		return $CODE_EXEC_ERROR
	fi
}

install_pre_requisites()
{
	check_pre_condition

	if [ "$OS" == "rhel" ]; then
		echo "Installing Prerequisite Packages for skc_library"
		dnf install -qy https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm || exit 1
		dnf install -qy https://dl.fedoraproject.org/pub/fedora/linux/releases/33/Everything/x86_64/os/Packages/s/softhsm-2.6.1-3.fc33.4.x86_64.rpm || exit 1
		dnf install -qy https://dl.fedoraproject.org/pub/fedora/linux/releases/33/Everything/x86_64/os/Packages/m/makeself-2.4.2-2.fc33.noarch.rpm || exit 1
		dnf install -qy https://dl.fedoraproject.org/pub/fedora/linux/releases/33/Everything/x86_64/os/Packages/l/libgda-5.2.9-6.fc33.x86_64.rpm || exit 1
		dnf install -qy https://dl.fedoraproject.org/pub/fedora/linux/releases/33/Everything/x86_64/os/Packages/l/libgda-devel-5.2.9-6.fc33.x86_64.rpm || exit 1
		dnf install -qy https://dl.fedoraproject.org/pub/fedora/linux/releases/33/Everything/x86_64/os/Packages/l/libgda-sqlite-5.2.9-6.fc33.x86_64.rpm | exit 1
		dnf groupinstall "Development Tools" -qy || exit 1
		dnf install -qy ${SKCLIB_PRE_REQUISITES} || exit 1
		ln -sf /usr/lib64/libjsoncpp.so /usr/lib64/libjsoncpp.so.0
		echo "RHEL Prerequisite Packages installed for skc_library"

	elif [ "$OS" == "ubuntu" ]; then
		apt update -y
		apt install -y build-essential automake autoconf libtool || exit 1
		apt install ${SKCLIB_PRE_REQUISITES} -y || exit 1
		apt install -y makeself libgda-5.0-4 libgda-5.0-dev || exit 1

		# Download P11-Kit
		wget http://archive.ubuntu.com/ubuntu/pool/main/libt/libtasn1-6/libtasn1-6_4.16.0-2_amd64.deb || exit 1
		wget http://archive.ubuntu.com/ubuntu/pool/main/libf/libffi/libffi8ubuntu1_3.4~20200819gead65ca871-0ubuntu3_amd64.deb || exit 1
		wget http://archive.ubuntu.com/ubuntu/pool/main/p/p11-kit/libp11-kit0_0.23.22-1_amd64.deb || exit 1
		wget http://archive.ubuntu.com/ubuntu/pool/main/p/p11-kit/libp11-kit-dev_0.23.22-1_amd64.deb || exit 1

		# Install p11-kit and its dependencies
		apt install -f ./libtasn1-6_4.16.0-2_amd64.deb || exit 1
		apt install -f ./libffi8ubuntu1_3.4~20200819gead65ca871-0ubuntu3_amd64.deb || exit 1
		apt install -f ./libp11-kit0_0.23.22-1_amd64.deb || exit 1
		apt install -f ./libp11-kit-dev_0.23.22-1_amd64.deb || exit 1

	        ln -sf /usr/lib/libjsoncpp.so /usr/lib/libjsoncpp.so.0
		# remove the downloaded files
		rm -rf *.deb
		echo "Ubuntu Prerequisite Packages installed for skc_library"
	fi

	# download and build latest libp11
	git clone https://github.com/OpenSC/libp11.git && cd libp11
	./bootstrap
	if [ "$OS" == "rhel" ]; then
		./configure --libdir=/usr/lib64/
	elif [ "$OS" == "ubuntu" ]; then
		./configure --libdir=/usr/lib/
	fi
	make install
	cd ..
	rm -rf libp11
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
