
AM_CPPFLAGS = $(COMMON_FLAGS) $(GMODULE_CFLAGS)

lib_LTLIBRARIES = \
    libcredential_agent.la

libcredential_agent_la_SOURCES = \
    init.c

libcredential_agent_la_LDFLAGS = -version-info @VERSION_INFO@ $(GLIB_LIBS) $(GMODULE_LIBS) \
	$(top_srcdir)/config-file/src/libkey_configfile.la


