SUBDIRS = \
	config-file \
	utils \
	credential-agent \
	key-agent \
	npm/kms \
	stm/sgx \
	api-module/pkcs11

GITCOMMIT := $(shell git describe --always)
VERSION=4.0.3

if PROXY_EXISTS
DOCKER_PROXY_FLAGS := --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy}
endif

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

docker:
	docker build ${DOCKER_PROXY_FLAGS} -f dist/image/Dockerfile -t isecl/skc-lib:$(VERSION) .
	docker save isecl/skc-lib:$(VERSION) > skc-lib-$(VERSION)-$(GITCOMMIT).tar

oci-archive: docker
	skopeo copy docker-daemon:isecl/skc-lib:$(VERSION) oci-archive:out/skc-lib-$(VERSION)-$(GITCOMMIT).tar
