
AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) -std=c++11 -fvisibility=hidden
AM_CPPFLAGS +=  \
	-I$(SGXSDK_INCDIR)

libdir = $(prefix)/lib/stm-modules

lib_LTLIBRARIES = \
    stm_sgx.la

stm_sgx_la_SOURCES = \
	init.cpp application_intf.cpp server_intf.cpp

stm_sgx_la_LDFLAGS = \
	-module -version-info @VERSION_INFO@ $(COMMON_LDFLAGS)
