#!/bin/bash

script_dir=$(dirname "$(readlink -f "$0")")
source ${script_dir}/config.ini

if [ -f ${script_dir}/$UTILS_SOURCE ]; then
    source ${script_dir}/$UTILS_SOURCE
else
    echo -e "Utils Script not found Error, Exit." && exit 1
fi

set_log $FLAG_ENABLE "SKC_WORKLOAD"

if [ -z "$1" ]; then
	exit_script $LOG_ERROR "Please give $0 <version>" $CODE_EXEC_ERROR
fi
ver="$1"

build_dir="${script_dir}/build"
bin_name="${SKC_COMPONENT_BIN_PREFIX}${ver}.bin"

rm -rf $build_dir/

if [ ! -d $SKC_COMPONENT_INSTALL_DIR ]; then
	exit_script $LOG_ERROR "${SKC_COMPONENT_INSTALL_DIR} is empty" $CODE_EXEC_ERROR
fi

# Create temperory directroy and copy the necessary scripts for packaging to self-installable binary
mkdir -p $SKC_DEVOPS_SCRIPTS_PATH
cp ${script_dir}/*common*.sh* ${script_dir}/*workload* ${script_dir}/*.ini $SKC_DEVOPS_SCRIPTS_PATH

mkdir -p $build_dir/scripts/

tar -cvf $build_dir/workload_bins.tar.gz $SKC_COMPONENT_INSTALL_DIR/
if [ $? -ne 0 ]; then
	exit_script $LOG_ERROR "Error in copy binaries from ${SKC_COMPONENT_INSTALL_DIR}" $CODE_EXEC_ERROR
fi 

# Remove the created temperory directory
rm -rf $SKC_COMPONENT_DEVOPS_DIR

log_msg $LOG_DEBUG "$script_dir"
cp ${script_dir}/*.sh ${script_dir}/*.ini $build_dir/scripts/
if [ $? -ne 0 ]; then
	ls ${script_dir}/*.sh
	exit_script $LOG_ERROR "Error in copy scripts" $CODE_EXEC_ERROR
fi 
sed -i 's/\(PROXY_REQUIRED=\)\(.*\)/\1"$FALSE"/' $build_dir/scripts/config.ini

cd $build_dir
SKC_COMPONENT_DEPLOY_SCRIPT="workload_install.sh"

echo "#!/bin/bash
echo \"DHSM 2.0 Workload Installation\"
source scripts/config.ini

if [ -f scripts/$UTILS_SOURCE ]; then
	source scripts/$UTILS_SOURCE
else
	echo -e \"Utils Script not found Error, Exit.\" && exit 1
fi
set_log $FLAG_ENABLE \"SKC_WORKLOAD\"

rm -rf $SKC_COMPONENT_INSTALL_DIR
sudo tar -xvf workload_bins.tar.gz -C /
curl -v -X GET \"https://api.trustedservices.intel.com/sgx/certification/v2/qe/identity\" -o /opt/skc/store/qeIdentity.json
chmod 777 /opt/skc/store/qeIdentity.json 
exit_script $LOG_DEBUG \"Workload Binaries Successfully Installaed\" $CODE_EXEC_SUCCESS

sudo mkdir -p $SKC_COMPONENT_DEVOPS_DIR

#Copy the packages to be installed to dependency_packages.txt file
echo \$SKC_COMPONENT_DEV_PRE_REQUISITES | tr \" \" \"\\n\" > \/$SKC_COMPONENT_DEVOPS_DIR/$SKC_WL_DEPENDENCY_PACKAGES

#Fetch installed dependency packages version
fetch_installed_dependency_packages_version \/$SKC_COMPONENT_DEVOPS_DIR/$SKC_WL_DEPENDENCY_PACKAGES \/$SKC_COMPONENT_DEVOPS_DIR/$SKC_WL_INSTALLED_DEPENDENCY_PACKAGES_VERSION

exit 0" > ${SKC_COMPONENT_DEPLOY_SCRIPT}
chmod 777 ${SKC_COMPONENT_DEPLOY_SCRIPT}
cd -

if [ -f $bin_name ]; then
	rm $bin_name
fi
makeself $build_dir $bin_name "WORKLOAD Self-Installer" ./${SKC_COMPONENT_DEPLOY_SCRIPT}
if [ $? -ne 0 ]; then
	log_msg $LOG_ERROR "Error in binary generation"
fi
exit_script $LOG_DEBUG "Binary Generation" $CODE_EXEC_SUCCESS
rm -rf $build_dir
