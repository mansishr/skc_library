SUBDIRS = \
	config-file \
	utils \
	credential-agent \
	key-agent \
	npm/kms \
	npm/reference \
	stm/sw \
	stm/sgx \
	api-module/pkcs11 \
	npm/tests/test_app

conf_dir:=./configs
datadir=$(prefix)/etc
storedir=$(prefix)/store
conf_files:=$(wildcard $(conf_dir)/*.ini) 
dest_conf_files=$(wildcard $(datadir)/*.ini) 
data_DATA=$(conf_files)

install-data-hook:$(dest_conf_files)
	@echo "calling install-data-hook:${dest_conf_files}"
	mkdir -p ${storedir}
	$(SED) -i \
                -e "s|__PREFIX__|@prefix@|" \
                -e "s|__SGXTOOLKIT__|$(SGXTOOLKIT)|" \
                -e "s|__CURL_BIN__|$(CURL_BIN)|" \
                $(dest_conf_files)

include_HEADERS = include/k_errors.h include/k_types.h
