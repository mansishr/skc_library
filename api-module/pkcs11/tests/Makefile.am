SUBDIRS=aes-test
conf_in=config.in
conf_out=config

install-data-hook:$(conf_in)
	$(SED) \
                -e "s|__PREFIX__|@prefix@|" \
                -e "s|__SGXTOOLKIT__|$(SGXTOOLKIT)|" \
                -e "s|__PWD__|$(PWD)|" \
                $(conf_in) > $(conf_out)
