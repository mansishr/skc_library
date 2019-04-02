AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) -std=c++11
#AM_CPPFLAGS += -DCMS

libdir = $(prefix)/lib/npm-modules

lib_LTLIBRARIES = \
    npm_reference.la

npm_reference_la_SOURCES = \
	cms.cpp \
    intf.cpp

npm_reference_la_LDFLAGS = -module -version-info @VERSION_INFO@ $(GLIB_LIBS) \
	-ljsoncpp \
	$(TOPDIR)/config-file/src/libkey_configfile.la



