AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) -std=c++11

lib_LTLIBRARIES = \
    libnpm_reference.la

npm_reference_la_SOURCES = \
    intf.cpp

libnpm_reference_la_LDFLAGS = -version-info @VERSION_INFO@ $(GLIB_LIBS)


