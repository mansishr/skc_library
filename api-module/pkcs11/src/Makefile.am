AM_CPPFLAGS = -I$(top_srcdir) -I$(TOPDIR)/SafeStringLibrary/include/ $(COMMON_FLAGS) \
	`pkg-config --cflags p11-kit-1` `pkg-config --cflags p11-kit-1 | sed "s| ||g"`/p11-kit \
	$(GMODULE_CFLAGS)  -std=c++11

if SGXTOOLKIT
AM_CPPFLAGS += \
	-DSGXTOOLKIT \
	-I$(SGXTOOLKIT)/include \
	-I$(SGXSDK_INCDIR)
endif

lib_LTLIBRARIES = \
    libpkcs11-api.la

SOURCES = \
	utils.c \
	pkcs11-apimodule.cpp \
	apimodule-sw.cpp

if SGXTOOLKIT
SOURCES += \
	apimodule-sgx.cpp
endif

libpkcs11_api_la_SOURCES = $(SOURCES)

libpkcs11_api_la_LDFLAGS = $(COMMON_LDFLAGS) -version-info @VERSION_INFO@ \
	$(GLIB_LIBS) \
	`pkg-config --libs p11-kit-1` \
	$(GMODULE_LIBS) \
	$(TOPDIR)/key-agent/src/libkey_agent.la \
	$(TOPDIR)/SafeStringLibrary/libSafeStringRelease.a

datadir=$(prefix)/etc
conf_file=pkcs11-apimodule.ini
dest_conf_file=$(datadir)/pkcs11-apimodule.ini
data_DATA=$(conf_file)

install-data-hook:
	@echo "calling install-data-hook:${dest_conf_file}"
	$(SED) -i \
		-e "s|__PREFIX__|@prefix@|" \
		-e "s|__SGXTOOLKIT__|$(SGXTOOLKIT)|" \
		$(dest_conf_file)
