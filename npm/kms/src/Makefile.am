
AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS)

libdir = $(prefix)/lib/npm-modules

lib_LTLIBRARIES = \
    npm_kms.la

npm_kms_la_SOURCES = \
    init.c

npm_kms_la_LDFLAGS = -module -version-info @VERSION_INFO@ $(GLIB_LIBS)


