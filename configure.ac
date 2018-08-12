##################
#                #
#    Version     #
#                #
################

# Program version

define([_VERSION_MAJOR], [2])
define([_VERSION_MINOR], [0])
define([_VERSION_FIX], [0])
define([PACKAGE_SUFFIX], [])

define([_VERSION_CURRENT], [2])
define([_VERSION_AGE], [1])
define([_VERSION_REVISION], [0])

##################
#                #
# Configure code #
#                #
##################

# Init
AC_PREREQ(2.61)
AC_INIT([DHSM2],[_VERSION_MAJOR._VERSION_MINOR._VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

# Version info for the library
VERSION_INFO="_VERSION_CURRENT:_VERSION_REVISION:_VERSION_AGE"
AC_SUBST(VERSION_INFO)

# Checks for compilers
AC_PROG_CC
AC_PROG_CXX

GLIB_TESTS

TOPDIR=${ac_pwd}
AC_SUBST(TOPDIR)

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.49.1])
PKG_CHECK_MODULES([GMODULE], [gmodule-2.0 >= 2.49.1])

COMMON_FLAGS="-I${TOPDIR}/include -I. -g $GLIB_CFLAGS -DG_LOG_USE_STRUCTURED"
AC_SUBST(COMMON_FLAGS)

# Set full directory paths
#full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
#full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
#full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
#libdir=$full_libdir

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

# Generate the libtool script and install script
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Generate the makefiles
AC_CONFIG_FILES([
	Makefile
	config-file/Makefile
	config-file/src/Makefile
	config-file/tests/Makefile
	credential-agent/Makefile
	credential-agent/commandline_tool/Makefile
	credential-agent/tests/Makefile
	key-agent/Makefile
	key-agent/src/Makefile
	key-agent/tests/Makefile
	npm/Makefile
	npm/kms/Makefile
	npm/kms/src/Makefile
	npm/kms/tests/Makefile
	npm/kmip/Makefile
	npm/kmip/src/Makefile
	npm/kmip/tests/Makefile
	stm/Makefile
	stm/sw/Makefile
	stm/sw/src/Makefile
	stm/sw/tests/Makefile
	stm/kpt/Makefile
	stm/kpt/src/Makefile
	stm/kpt/tests/Makefile
])

AC_OUTPUT
