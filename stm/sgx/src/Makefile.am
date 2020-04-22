AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(LIBCURL_CPPFLAGS) -std=c++11 -fvisibility=hidden
AM_CPPFLAGS +=  \
	-I$(SGXSDK_INCDIR)

libdir = $(prefix)/lib/stm-modules

lib_LTLIBRARIES = \
    stm_sgx.la

stm_sgx_la_SOURCES = \
	application_intf.cpp

stm_sgx_la_LDFLAGS = \
	-module -version-info @VERSION_INFO@ \
	$(COMMON_LDFLAGS) \
	$(TOPDIR)/utils/libskc_utils.la \
	$(TOPDIR)/config-file/src/libkey_configfile.la
