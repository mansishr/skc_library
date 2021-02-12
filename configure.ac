##################
#                #
#    Version     #
#                #
################

# Program version

define([_VERSION_MAJOR], [3])
define([_VERSION_MINOR], [4])
define([_VERSION_FIX], [0])
define([PACKAGE_SUFFIX], [])

define([_VERSION_CURRENT], [3])
define([_VERSION_AGE], [3])
define([_VERSION_REVISION], [0])
define([AM_CXXFLAGS], [-std=c++0x])

##################
#                #
# Configure code #
#                #
##################

# Init
AC_PREREQ(2.61)
AC_INIT([SKC],[_VERSION_MAJOR._VERSION_MINOR._VERSION_FIX[]PACKAGE_SUFFIX])
#LT_INIT([shared disable-static])
AC_CONFIG_AUX_DIR([configout])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

# Checks for compilers
AC_PROG_CC
AC_PROG_CXX

SKC_LIBCURL_CHECK_CONF
SKC_SETUP(.)
SGX_MODE_CHECK

# Define some variables for the code
AC_DEFINE_UNQUOTED(
	[VERSION_MAJOR],
	[_VERSION_MAJOR],
	[major version number]
)
AC_DEFINE_UNQUOTED(
	[VERSION_MINOR],
	[_VERSION_MINOR],
	[minor version number]
)

AC_DEFINE_UNQUOTED(
	[HAVE_CXX11],
	[1],
	[Use C++11 compiler]
)

AC_DEFINE_UNQUOTED(
	[HAVE_CXX14],
	[1],
	[Use C++14 compiler]
)

# Generate the libtool script and install script
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Generate the makefiles
AC_CONFIG_FILES([
	Makefile
	credential-agent/Makefile
	credential-agent/commandline_tool/Makefile
	utils/Makefile
])

AC_CONFIG_SUBDIRS([
    config-file
    key-agent
    stm/sw
    stm/sgx
    npm/kms
    api-module/pkcs11
])

AC_OUTPUT
