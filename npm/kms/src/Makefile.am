
AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) -std=c++11
AM_CPPFLAGS += -DCMS=1

libdir = $(prefix)/lib/npm-modules

lib_LTLIBRARIES = \
    npm_kms.la

npm_kms_la_SOURCES = \
	cms.cpp \
    intf.cpp

npm_kms_la_LDFLAGS = -module -version-info @VERSION_INFO@ $(GLIB_LIBS) \
	$(TOPDIR)/config-file/src/libkey_configfile.la \
	-ljsoncpp
