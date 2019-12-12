# Increment this whenever this file is changed.
#serial 1

dnl DHSM_SETUP
dnl

AC_DEFUN([DHSM_SETUP],
[
    PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.49.1])
    PKG_CHECK_MODULES([GMODULE], [gmodule-2.0 >= 2.49.1])

    VERSION_INFO="_VERSION_CURRENT:_VERSION_REVISION:_VERSION_AGE"
    AC_SUBST(VERSION_INFO)

	full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"` 
	default_skc_conf_path="`eval echo ${full_sysconfdir} | sed s,NONE,$ac_default_prefix,g`"
	default_skc_install_path="`eval echo ${prefix} | sed s,NONE,$ac_default_prefix,g`"

    GLIB_TESTS
    TOPDIR="$srcdir/$1"
    TOPDIR=`cd "$srcdir/$1" && pwd -P`
    AC_SUBST(TOPDIR)
    COMMON_FLAGS="-I${TOPDIR}/include -I${TOPDIR} -I. -g -O0 $GLIB_CFLAGS -DG_LOG_USE_STRUCTURED"
    COMMON_LDFLAGS="$GLIB_LIBS"
	AC_PREFIX_DEFAULT(/tmp/foo)
    AC_SUBST(COMMON_FLAGS)
    AC_SUBST(COMMON_LDFLAGS)
    AC_SUBST(GLIB_FLAGS)
    AC_SUBST(GLIB_LIBS)
#AC_DEFINE_UNQUOTED(SKC_KEYAGENT_DLL_API_VISIBLITY, 1, [Enable API visibility in keyagent.so] )
	AC_DEFINE_UNQUOTED(
		[SKC_CONF_PATH],
		["$default_skc_conf_path"],
		[The default location of configuration file directory]
	)
	 
	AC_SUBST([default_skc_conf_path])

	AC_DEFINE_UNQUOTED(
		[SKC_INSTALL_DIR],
		["$default_skc_install_path"],
		[The default installation directory]
	)
	AC_SUBST([default_skc_install_path])
])

