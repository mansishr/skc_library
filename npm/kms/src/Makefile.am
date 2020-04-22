AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) -std=c++11

libdir = $(prefix)/lib/npm-modules

lib_LTLIBRARIES = \
    npm_kms.la

npm_kms_la_SOURCES = \
    intf.cpp

npm_kms_la_LDFLAGS = -module -version-info @VERSION_INFO@ $(GLIB_LIBS) \
	$(TOPDIR)/config-file/src/libkey_configfile.la \
	$(TOPDIR)/utils/libskc_utils.la \
	-ljsoncpp
