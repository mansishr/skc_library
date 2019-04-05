# SGX_INIT()
# ------------------
AC_DEFUN([SGX_INIT],[
	AC_ARG_WITH([enclave-libdir],
		[AS_HELP_STRING([--with-enclave-libdir=path (default: EPREFIX/lib)],
			[Set the directory where enclave libraries should be installed])
		], [enclave_libdir=$withval], [enclave_libdir="${prefix}/lib"],
                   [echo "--with-enclave-libdir option not set. Defaults to ${prefix}/lib/"; enclave_libdir=${prefix}/lib])
	AC_SUBST(enclave_libdir)
	AC_DEFINE_UNQUOTED([ENCLAVE_LIBDIR_PATH], "${enclave_libdir}", [Enclave library path])
	AC_ARG_ENABLE([sgx-simulation],
		[AS_HELP_STRING([--enable-sgx-simulation (default: disabled)],
			[Use Intel SGX in simulation mode])
		], [_sgxsim=yes], [_sgxsim=no])
	AS_IF([test "x$_sgxsim" = "xyes"], [
			AC_SUBST(SGX_TRTS_LIB, [sgx_trts_sim])
			AC_SUBST(SGX_TSERVICE_LIB, [sgx_tservice_sim])
			AC_SUBST(SGX_UAE_SERVICE_LIB, [sgx_uae_service_sim])
			AC_SUBST(SGX_URTS_LIB, [sgx_urts_sim])
		], [
			AC_SUBST(SGX_TRTS_LIB, [sgx_trts])
			AC_SUBST(SGX_TSERVICE_LIB, [sgx_tservice])
			AC_SUBST(SGX_UAE_SERVICE_LIB, [sgx_uae_service])
			AC_SUBST(SGX_URTS_LIB, [sgx_urts])
		]
	)
	AC_ARG_WITH([sgx-build],
		[AS_HELP_STRING([--with-sgx-build=debug|prerelease|release (default: debug)],
			[Set Intel SGX build mode])
		], [_sgxbuild=$withval], [_sgxbuild=debug])
	AS_IF([test "x$_sgxbuild" = "xdebug"], [
			AC_DEFINE(DEBUG, 1, [Enable debugging])
			AC_SUBST(ENCLAVE_SIGN_TARGET, [signed_enclave_dev])
		],
		[test "x$_sgxbuild" = "xprerelease"], [
			AC_DEFINE(NDEBUG, 1, [Flag set for prerelease and release builds])
			AC_DEFINE(EDEBUG, 1, [Flag set for prerelease builds])
			AC_SUBST(ENCLAVE_SIGN_TARGET, [signed_enclave_dev])
		],
		[test "x$_sgxbuild" = "xrelease"], [
			AS_IF(test "x$_sgxsim" = "xyes", [
				AC_MSG_ERROR([Can't build in both release and simulation mode])
			],
			[
				AC_DEFINE(NDEBUG, 1)
				AC_SUBST(ENCLAVE_SIGN_TARGET, [signed_enclave_rel])
			])
		],
		[AC_MSG_ERROR([Unknown build mode $_sgxbuild])]
	)
	AC_SUBST(SGX_DEBUG_FLAGS, [$_sgxdebug])
	AS_IF([test "x$SGX_SDK" = "x"], [SGXSDKDIR=detect], [SGXSDKDIR=env])
	AC_ARG_WITH([sgxsdk],
		[AS_HELP_STRING([--with-sgxsdk=path],
			[Set the path to your Intel SGX SDK directory])
		], [SGXSDKDIR=$withval],[SGXSDKDIR="detect"])
	AS_IF([test "x$SGXSDKDIR" = "xenv"], [],
		[test "x$SGXSDKDIR" != "xdetect"], [],
		[test -d /opt/intel/sgxsdk], [SGXSDKDIR=/opt/intel/sgxsdk],
		[test -d ~/sgxsdk], [SGXSDKDIR=~/sgxsdk],
		[test -d ./sgxsdk], [SGXSDKDIR=./sgxsdk],
		[AC_ERROR([Can't detect your Intel SGX SDK installation directory])])
	AS_IF([test -d $SGXSDKDIR/lib], [AC_SUBST(SGXSDK_LIBDIR, $SGXSDKDIR/lib)],
        	[test -d $SGXSDKDIR/lib64], [AC_SUBST(SGXSDK_LIBDIR, $SGXSDKDIR/lib64)],
        	[AC_ERROR(Can't find Intel SGX SDK lib directory)])
	AS_IF([test -d $SGXSDKDIR/bin/ia32], [AC_SUBST(SGXSDK_BINDIR, $SGXSDKDIR/bin/ia32)],
        	[test -d $SGXSDKDIR/bin/x64], [AC_SUBST(SGXSDK_BINDIR, $SGXSDKDIR/bin/x64)],
        	[AC_ERROR(Can't find Intel SGX SDK bin directory)])
	AC_MSG_NOTICE([Found your Intel SGX SDK in $SGXSDKDIR])
	AC_SUBST(SGXSDK_INCDIR, $SGXSDKDIR/include)
	AC_SUBST(SGXSDKDIR)
	#AC_CONFIG_FILES([sgx_app.mk])

	AS_IF([test "x$SGX_SSL" = "x"], [SGXSSLDIR=detect], [SGXSSLDIR=env])
	AC_ARG_WITH([sgxssl-libdir],
		[AS_HELP_STRING([--with-sgxssl-libdir=path (default: /opt/intel/sgxssl)],
			[Set the directory where intel sgxssl libraries are located])
		], [SGXSSLDIR=$withval], [SGXSSLDIR="detect"])
        AS_IF([test "x$SGXSSLDIR" = "xenv"], [],
                [test "x$SGXSSLDIR" != "xdetect"], [],
                [test -d /opt/intel/sgxssl], [SGXSSLDIR=/opt/intel/sgxssl],
                [test -d ~/sgxssl], [SGXSSLDIR=~/sgxssl],
                [test -d ./sgxssl], [SGXSSLDIR=./sgxssl],
                [AC_ERROR([Can't detect your Intel SGX SSL installation directory])])
        AS_IF([test -d $SGXSSLDIR/lib], [AC_SUBST(SGXSSL_LIBDIR, $SGXSSLDIR/lib)],
                [test -d $SGXSDKDIR/lib64], [AC_SUBST(SGXSSL_LIBDIR, $SGXSSLDIR/lib64)],
                [AC_ERROR(Can't find Intel SGX SSL lib directory)])
        AC_MSG_NOTICE([Found your Intel SGX SSL in $SGXSSLDIR])
	AC_SUBST(SGXSSLDIR)

	AC_ARG_WITH([sgx-toolkit],
		[AS_HELP_STRING([--with-sgx-toolkit=path],
			[Set the directory where sgx toolkit is installed])
		], [SGXTOOLKIT=$withval], [])

	AC_SUBST(SGXTOOLKIT)
    AM_CONDITIONAL([SGXTOOLKIT], [test "x$SGXTOOLKIT" != "x"])
])

