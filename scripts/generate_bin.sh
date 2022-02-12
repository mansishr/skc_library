#!/bin/bash

script_dir=$(dirname "$(readlink -f "$0")")

# Check OS and VERSION
OS=$(cat /etc/os-release | grep ^ID= | cut -d'=' -f2)
temp="${OS%\"}"
temp="${temp#\"}"
OS="$temp"
VER=$(cat /etc/os-release | grep ^VERSION_ID | tr -d 'VERSION_ID="')

if [ "$OS" == "rhel" ]
then
source ${script_dir}/config_rhel.ini
elif [ "$OS" == "ubuntu" ]
then
source ${script_dir}/config_ubuntu.ini
fi

source ${script_dir}/$UTILS_SOURCE

set_log $FLAG_ENABLE "skc_library"

if [ -z "$1" ]; then
	exit_script $LOG_ERROR "Please provide $0 <version>" $CODE_EXEC_ERROR
fi
ver="$1"

build_dir="${script_dir}/build"
bin_name="${SKCLIB_BIN_PREFIX}${ver}.bin"

rm -rf $build_dir/

if [ ! -d $SKCLIB_INSTALL_DIR ]; then
	exit_script $LOG_ERROR "${SKCLIB_INSTALL_DIR} is empty" $CODE_EXEC_ERROR
fi

# Create temp directory and copy the necessary scripts for packaging to self-installable binary
mkdir -p $SKC_DEVOPS_SCRIPTS_PATH
cp ${script_dir}/*common*.sh* ${script_dir}/*uninstall* ${script_dir}/*.ini $SKC_DEVOPS_SCRIPTS_PATH

mkdir -p $build_dir/scripts/

chmod go-rwx $SKCLIB_INSTALL_DIR
tar -cf $build_dir/skc_library.tar.gz $SKCLIB_INSTALL_DIR/
if [ $? -ne 0 ]; then
	exit_script $LOG_ERROR "Error while copying binaries from ${SKCLIB_INSTALL_DIR}" $CODE_EXEC_ERROR
fi 

# Remove the created temp directory
rm -rf $SKCLIB_DEVOPS_DIR

log_msg $LOG_DEBUG "$script_dir"
cp ${script_dir}/*.sh ${script_dir}/*.ini $build_dir/scripts/
if [ $? -ne 0 ]; then
	ls ${script_dir}/*.sh
	exit_script $LOG_ERROR "Error while copying scripts" $CODE_EXEC_ERROR
fi 

cd $build_dir
SKCLIB_DEPLOY_SCRIPT="skc_library_install.sh"

echo "#!/bin/bash
echo \"skc_library installation\"

if [ "$OS" == "rhel" ]
then
source scripts/config_rhel.ini
elif [ "$OS" == "ubuntu" ]
then
source scripts/config_ubuntu.ini
fi

if [ $VER == "20.04" ]; then
        SKCLIB_PRE_REQUISITES=$SKCLIB_PRE_REQUISITES_UB_UPGRADED_VER
fi

source scripts/$UTILS_SOURCE
set_log $FLAG_ENABLE \"skc_library\"

rm -rf $SKCLIB_INSTALL_DIR
tar -xf skc_library.tar.gz -C /
exit_script $LOG_DEBUG \"skc_library installed\" $CODE_EXEC_SUCCESS

mkdir -p $SKCLIB_DEVOPS_DIR

#Copy the packages to be installed to dependency_packages.txt file
echo \$SKCLIB_PRE_REQUISITES | tr \" \" \"\\n\" > \/$SKCLIB_DEVOPS_DIR/$SKCLIB_DEPS_PACKAGES

#Fetch installed dependency packages version
fetch_installed_dependency_packages_version \/$SKCLIB_DEVOPS_DIR/$SKCLIB_DEPS_PACKAGES \/$SKCLIB_DEVOPS_DIR/$SKCLIB_INSTALLED_DEPS_PACKAGES_VER

exit 0" > ${SKCLIB_DEPLOY_SCRIPT}
chmod 500 ${SKCLIB_DEPLOY_SCRIPT}
cd -

if [ -f $bin_name ]; then
	rm $bin_name
fi
makeself $build_dir $bin_name "skc_library self installer" ./${SKCLIB_DEPLOY_SCRIPT}
if [ $? -ne 0 ]; then
	log_msg $LOG_ERROR "could not create skc_library install binary"
fi
exit_script $LOG_DEBUG "skc_library install binary generated" $CODE_EXEC_SUCCESS
rm -rf $build_dir
