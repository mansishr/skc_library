AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) -std=c++11

libdir = $(prefix)/lib/npm-modules

lib_LTLIBRARIES = \
    npm_reference.la

npm_reference_la_SOURCES = \
    intf.cpp

npm_reference_la_LDFLAGS = -module -version-info @VERSION_INFO@ $(GLIB_LIBS) \
	-ljsoncpp \
	$(TOPDIR)/config-file/src/libkey_configfile.la \
	$(TOPDIR)/utils/libskc_utils.la



