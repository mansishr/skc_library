
AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS)

libdir = $(prefix)/lib/stm-modules

lib_LTLIBRARIES = \
    stm_kpt.la

stm_kpt_la_SOURCES = \
    init.c

stm_kpt_la_LDFLAGS = -module -version-info @VERSION_INFO@ $(GLIB_LIBS)


