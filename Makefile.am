
SUBDIRS = \
	config-file \
	credential-agent \
	key-agent \
	npm/kms \
	npm/reference \
	stm/sw \
	api-module/pkcs11 \
	npm/tests/test_app

if SGXTOOLKIT
SUBDIRS += \
	stm/sgx
endif

conf_dir:=./configs
datadir=$(prefix)/etc
conf_files:=$(wildcard $(conf_dir)/*.ini) 
dest_conf_files=$(wildcard $(datadir)/*.ini) 
data_DATA=$(conf_files)

install-data-hook:$(dest_conf_files)
	@echo "calling install-data-hook:${dest_conf_files}"
	$(SED) -i \
                -e "s|__PREFIX__|@prefix@|" \
                -e "s|__SGXTOOLKIT__|$(SGXTOOLKIT)|" \
                $(dest_conf_files)

include_HEADERS = include/k_errors.h include/k_types.h
