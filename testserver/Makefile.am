RESTBED_PREFIX = $(HOME)/skc/distributed_hsm-restbed
MYLDFLAGS = -L/usr/local/lib64 -Wl,-rpath=/usr/local/lib64  -Wl,-rpath=$(RESTBED_PREFIX)/distribution/library -L$(RESTBED_PREFIX)/distribution/library $(OPENSSL_LIBS) -lssl -lrestbed -ljsoncpp -lcrypto

AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(GMODULE_CFLAGS) -std=c++11  -I$(RESTBED_PREFIX)/distribution/include -I$(RESTBED_PREFIX)/dependency/openssl/include

bin_PROGRAMS = testserver

testserver_SOURCES = \
	testserver.cpp key_transfer_intf.cpp utils.cpp key_usage_polices.cpp

testserver_LDFLAGS = -version-info @VERSION_INFO@ $(GLIB_LIBS) $(GMODULE_LIBS) \
	$(top_srcdir)/config-file/src/libkey_configfile.la $(MYLDFLAGS) -I$(RESTBED_PREFIX)/dependency/openssl/include 

scripts_dir:=./certs
datadir=$(prefix)/store/testserver
script_files:=$(wildcard $(scripts_dir)/*.sh $(scripts_dir)/*.cnf) 
dest_script_files=$(wildcard $(datadir)/*.sh $(datadir)/*.cnf) 
data_DATA=$(script_files)

install-data-hook:$(dest_script_files)
	mkdir -p $(datadir)
	@echo "calling install-data-hook:${dest_script_files}"
	$(SED) -i "s|__PREFIX__|@prefix@|" $(dest_script_files)
	chmod a+x $(dest_script_files)
	$(dest_script_files)
