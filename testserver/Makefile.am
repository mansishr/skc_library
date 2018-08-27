

RESTBED_PREFIX	=	$(HOME)/dhsm/restbed/distribution/
MYLDFLAGS	= -L/usr/local/lib64 -Wl,-rpath=/usr/local/lib64  -Wl,-rpath=$(RESTBED_PREFIX)/library -L$(RESTBED_PREFIX)/library -lcrypto -lssl -lrestbed -lcrypto -ljsoncpp 

AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(GMODULE_CFLAGS) -std=c++11  -I$(RESTBED_PREFIX)/include

bin_PROGRAMS = testserver

testserver_SOURCES = \
	testserver.cpp key_transfer_intf.cpp utils.cpp


testserver_LDFLAGS = -version-info @VERSION_INFO@ $(GLIB_LIBS) $(GMODULE_LIBS) \
	$(top_srcdir)/config-file/src/libkey_configfile.la $(MYLDFLAGS)



