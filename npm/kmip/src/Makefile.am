AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS)

libdir = $(prefix)/lib/npm-modules

lib_LTLIBRARIES = \
    npm_kmip.la

npm_kmip_la_SOURCES = \
    init.c

npm_kmip_la_LDFLAGS = -module -version-info @VERSION_INFO@ $(GLIB_LIBS) \
	$(TOPDIR)/config-file/src/libkey_configfile.la

