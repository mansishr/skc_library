#!/bin/bash
script_dir=$(dirname $0)
source ${script_dir}/config.ini

if [ -f ${script_dir}/$UTILS_SOURCE ]; then
    source ${script_dir}/$UTILS_SOURCE
else
    echo -e "Utils Script not found Error, Exit." && exit 1
fi

set_log $FLAG_ENABLE "DHSM2_WORKLOAD"

if [ -z "$1" ]; then
	exit_script $LOG_ERROR "Please give $0 <version>" $CODE_EXEC_ERROR
fi
ver="$1"

install_pre_requisites "devOps"

build_dir="${script_dir}/build"
bin_name="${DHSM2_COMPONENT_BIN_PREFIX}${ver}.bin"

rm -rf $build_dir/

if [ ! -d $DHSM2_COMPONENT_INSTALL_DIR ]; then
	exit_script $LOG_ERROR "${DHSM2_COMPONENT_INSTALL_DIR} is empty" $CODE_EXEC_ERROR
fi


mkdir -p $build_dir/scripts/

tar -cvf $build_dir/workload_bins.tar.gz $DHSM2_COMPONENT_INSTALL_DIR/
if [ $? -ne 0 ]; then
	exit_script $LOG_ERROR "Error in copy binaries from ${DHSM2_COMPONENT_INSTALL_DIR}" $CODE_EXEC_ERROR
fi 

log_msg $LOG_DEBUG "$script_dir"
cp ${script_dir}/*.sh ${script_dir}/*.ini $build_dir/scripts/
if [ $? -ne 0 ]; then
	ls ${script_dir}/*.sh
	exit_script $LOG_ERROR "Error in copy scripts" $CODE_EXEC_ERROR
fi 
sed -i 's/\(PROXY_REQUIRED=\)\(.*\)/\1"$FALSE"/' $build_dir/scripts/config.ini

cd $build_dir
DHSM2_COMPONENT_DEPLOY_SCRIPT="workload_install.sh"

echo "#!/bin/bash
echo \"DHSM 2.0 Workload Installation\"
source scripts/config.ini

if [ -f scripts/$UTILS_SOURCE ]; then
	source scripts/$UTILS_SOURCE
else
	echo -e \"Utils Script not found Error, Exit.\" && exit 1
fi
set_log $FLAG_ENABLE \"DHSM2_WORKLOAD\"
install_pre_requisites
if [ $? -ne $CODE_EXEC_SUCCESS ]; then
	exit_script $LOG_ERROR "Pre-requisties installation" $CODE_ERROR
fi
rm -rf $DHSM2_COMPONENT_INSTALL_DIR
#sudo mkdir $DHSM2_COMPONENT_INSTALL_DIR
sudo tar -xvf workload_bins.tar.gz -C /
exit 0" > ${DHSM2_COMPONENT_DEPLOY_SCRIPT}

chmod 777 ${DHSM2_COMPONENT_DEPLOY_SCRIPT}
cd -

if [ -f $bin_name ]; then
	rm $bin_name
fi
makeself $build_dir $bin_name "WORKLOAD Self-Installer" ./${DHSM2_COMPONENT_DEPLOY_SCRIPT}
if [ $? -ne 0 ]; then
	log_msg $LOG_ERROR "Error in binary generation"
fi
exit_script $LOG_DEBUG "Binary Generation" $CODE_EXEC_SUCCESS
rm -rf $build_dir
