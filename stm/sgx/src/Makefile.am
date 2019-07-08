AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(LIBCURL_CPPFLAGS) -std=c++11 -fvisibility=hidden
AM_CPPFLAGS +=  \
	 $(OPENSSL_INCLUDES) \
	-I$(SGXSDK_INCDIR)

libdir = $(prefix)/lib/stm-modules

lib_LTLIBRARIES = \
    stm_sgx.la

stm_sgx_la_SOURCES = \
	init.cpp application_intf.cpp server_intf.cpp sgx_epid_quote_verify.cpp sgx_ecdsa_quote_verify.cpp

stm_sgx_la_LDFLAGS = \
	-module -version-info @VERSION_INFO@ \
	$(OPENSSL_LIBS) \
	$(COMMON_LDFLAGS) \
	-L$(SGXSDK_LIBDIR) -lQuoteVerification \
	$(TOPDIR)/utils/libskc_utils.la \
	$(TOPDIR)/config-file/src/libkey_configfile.la \
	-lcrypto \
	-lcurl \
	-ljsoncpp \
        -L$(SGXSDK_LIBDIR) -lsgx_uae_service	

