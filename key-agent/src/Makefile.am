
AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(GMODULE_CFLAGS)

lib_LTLIBRARIES = \
    libkey_agent.la

libkey_agent_la_SOURCES = \
    init.c \
	key_init.c

libkey_agent_la_LDFLAGS = -version-info @VERSION_INFO@ $(GLIB_LIBS) $(GMODULE_LIBS) \
	$(top_srcdir)/config-file/src/libkey_configfile.la 
