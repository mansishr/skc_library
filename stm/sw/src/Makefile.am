
AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) -std=c++11


libdir = $(prefix)/lib/stm-modules

lib_LTLIBRARIES = \
    stm_sw.la

stm_sw_la_SOURCES = \
	init.cpp application_intf.cpp server_intf.cpp

stm_sw_la_LDFLAGS = -module -version-info @VERSION_INFO@ $(COMMON_LDFLAGS)
