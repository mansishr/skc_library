AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(GMODULE_CFLAGS) -std=c++11

lib_LTLIBRARIES = \
    libkey_agent.la

libkey_agent_la_SOURCES = \
    intf.cpp \
    curl.cpp \
    cert.cpp \
	utils.cpp \
	../npm/npm_init.cpp \
	../stm/stm_init.cpp \
	key_init.cpp

libkey_agent_la_LDFLAGS = -version-info @VERSION_INFO@ -lcurl -lcrypto $(COMON_LDFLAGS) $(GMODULE_LIBS) \
	$(TOPDIR)/config-file/src/libkey_configfile.la
