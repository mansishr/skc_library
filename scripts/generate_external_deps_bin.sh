#!/bin/bash
script_dir=$(dirname "$(readlink -f "$0")")
source ${script_dir}/config.ini

if [ -f ${script_dir}/$UTILS_SOURCE ]; then
    source ${script_dir}/$UTILS_SOURCE
else
    echo -e "Utils Script not found Error, Exit." && exit 1
fi

set_log $FLAG_ENABLE "SKC_WORKLOAD_EXT_BIN"

if [ -z "$1" ]; then
	exit_script $LOG_ERROR "Please give $0 <version>" $CODE_EXEC_ERROR
fi
ver="$1"

if [ $SKC_PRIVATE_KEY_SUPPORT != $TRUE ]; then
        log_msg $LOG_DEBUG "PRIVATE_KEY_SUPPORT disabled so skipping external binary generation" 
	exit $CODE_EXEC_SUCCESS
fi

install_pre_requisites "devOps"

build_dir="${script_dir}/build_ext_deps"
bin_name="${SKC_COMPONENT_EXT_DEPS_BIN_PREFIX}${ver}.bin"

rm -rf $build_dir/

if [ ! -d $SKC_COMPONENT_EXT_LIBCURL_INSTALL_DIR ]; then
	exit_script $LOG_ERROR "${SKC_COMPONENT_EXT_LIBCURL_INSTALL_DIR} or ${SKC_COMPONENT_EXT_OPENSSL_INSTALL_DIR} is empty" $CODE_EXEC_ERROR
fi

mkdir -p $build_dir/scripts/

tar -cvf $build_dir/workload_deps_bins.tar.gz $SKC_COMPONENT_EXT_LIBCURL_INSTALL_DIR
if [ $? -ne 0 ]; then
	exit_script $LOG_ERROR "Error in generation of tar" $CODE_EXEC_ERROR
fi 

log_msg $LOG_DEBUG "$script_dir"
cp ${script_dir}/*.sh ${script_dir}/*.ini $build_dir/scripts/
if [ $? -ne 0 ]; then
	ls ${script_dir}/*.sh
	exit_script $LOG_ERROR "Error in copy scripts" $CODE_EXEC_ERROR
fi 
sed -i 's/\(PROXY_REQUIRED=\)\(.*\)/\1"$FALSE"/' $build_dir/scripts/config.ini

cd $build_dir
SKC_COMPONENT_DEPLOY_SCRIPT="workload_deps_install.sh"

echo "#!/bin/bash
echo \"DHSM 2.0 Workload DEPS Installation\"
source scripts/config.ini

if [ -f scripts/$UTILS_SOURCE ]; then
	source scripts/$UTILS_SOURCE
else
	echo -e \"Utils Script not found Error, Exit.\" && exit 1
fi

set_log $FLAG_ENABLE \"SKC_WORKLOAD_DEPS\"
install_pre_requisites
if [ $? -ne $CODE_EXEC_SUCCESS ]; then
	exit_script $LOG_ERROR "Pre-requisties installation" $CODE_ERROR
fi

curl_lib_cnt=\$(get_file_count \"libcurl.so.$SKC_COMPONENT_REQ_LIB_CURL_VER*\")
log_msg $LOG_DEBUG \"Count: curl: \$curl_lib_cnt\"

if [ \$curl_lib_cnt -eq 0 ]; then
	log_msg $LOG_DEBUG \"Installing Deps\"
	sudo tar -xvf workload_deps_bins.tar.gz -C /
	log_msg $LOG_DEBUG \"External Deps successfully installed\"
else
	log_msg $LOG_DEBUG \"External Deps already installed\"
fi

exit 0" > ${SKC_COMPONENT_DEPLOY_SCRIPT}

chmod 777 ${SKC_COMPONENT_DEPLOY_SCRIPT}
cd -

if [ -f $bin_name ]; then
	rm $bin_name
fi
makeself $build_dir $bin_name "Workload Depdency Self-Installer" ./${SKC_COMPONENT_DEPLOY_SCRIPT}
if [ $? -ne 0 ]; then
	log_msg $LOG_ERROR "Error in binary generation"
fi
exit_script $LOG_DEBUG "Workload Deps Binary Generation" $CODE_EXEC_SUCCESS
rm -rf $build_dir
