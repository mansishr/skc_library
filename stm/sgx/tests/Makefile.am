AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(LIBCURL_CPPFLAGS) -std=c++11 -fvisibility=hidden
AM_CPPFLAGS +=  \
	 $(OPENSSL_INCLUDES) \
	-I$(SGXSDK_INCDIR)

noinst_PROGRAMS = \
   sgx-epid-quote-verify 

sgx_epid_quote_verify_SOURCES=sgx_epid_quote_verify_test.cpp ../src/sgx_epid_quote_verify.cpp

sgx_epid_quote_verify_LDFLAGS = \
	-lcrypto \
	-lcurl \
	-ljsoncpp \
        -L$(SGXSDK_LIBDIR) -lsgx_uae_service	

sgx_epid_quote_verify_LDADD = \
	$(TOPDIR)/config-file/src/libkey_configfile.la \
	$(TOPDIR)/utils/libskc_utils.la


