SUBDIRS = \  
    curl \
	config-file \
	credential-agent \
	key-agent \
	npm/kms \
	npm/reference \
	stm/sw \
	api-module/sw-pkcs11/SoftHSMv2 \
	npm/tests/test_app

conf_dir:=./configs
datadir=$(prefix)/etc
conf_files:=$(wildcard $(conf_dir)/*.ini) 
dest_conf_files=$(wildcard $(datadir)/*.ini) 
data_DATA=$(conf_files)

install-data-hook:$(dest_conf_files)
	@echo "calling install-data-hook:${dest_conf_files}"
	$(SED) -i "s|__PREFIX__|@prefix@|" $(dest_conf_files)

include_HEADERS = include/k_errors.h
