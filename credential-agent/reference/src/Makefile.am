
AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS)

libdir = $(prefix)/lib/credential-modules

lib_LTLIBRARIES = \
    reference.la

reference_la_SOURCES = \
    init.c

reference_la_LDFLAGS = -module -version-info @VERSION_INFO@ $(GLIB_LIBS)


