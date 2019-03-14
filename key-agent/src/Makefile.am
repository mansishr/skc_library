AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(GMODULE_CFLAGS) $(GDA_CFLAGS) $(OPENSSL_INCLUDES) -std=c++11 -DPKGDATA="\"$(prefix)\""

lib_LTLIBRARIES = \
    libkey_agent.la

libkey_agent_la_SOURCES = \
    intf.cpp \
    curl.cpp \
    cert.cpp \
	utils.cpp \
	../npm/npm_init.cpp \
	../stm/stm_init.cpp \
	cache-init.cpp \
	cache-session.cpp \
	session.cpp \
	key.cpp \
	cache-key.cpp

libkey_agent_la_LDFLAGS = -version-info @VERSION_INFO@ $(OPENSSL_LIBS) $(COMMON_LDFLAGS) $(GMODULE_LIBS) $(GDA_LIBS) \
	$(TOPDIR)/config-file/src/libkey_configfile.la ${TOPDIR}/curl/lib/libcurl.la
