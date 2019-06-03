AC_DEFUN([SKC_LIBCURL_CHECK_CONF],
[
  AC_ARG_WITH(libcurl,
     AC_HELP_STRING([--with-libcurl=PREFIX],[look for the curl library in PREFIX/lib and headers in PREFIX/include]),
     [_libcurl_with=$withval],[_libcurl_with=ifelse([$1],,[yes],[$1])])


     AC_PROG_AWK
     if test -d "$_libcurl_with" ; then
        LIBCURL_CPPFLAGS="-I$withval/include"
        _libcurl_ldflags="-L$withval/lib"
        AC_PATH_PROG([CURL_BIN],[curl],[],
                     ["$withval/bin"])
        AC_PATH_PROG([_libcurl_config],[curl-config],[],
                     ["$withval/bin"])
     else
        AC_PATH_PROG([_libcurl_config],[curl-config],[],[$PATH])
        AC_PATH_PROG([CURL_BIN],[curl],[],[$PATH])
     fi

     if test x"$LIBCURL_CPPFLAGS" = "x" ; then
           LIBCURL_CPPFLAGS=`$_libcurl_config --cflags`
     fi
     if test x"$LIBCURL" = "x" ; then
              LIBCURL=`$_libcurl_config --libs`
     fi
     AC_MSG_NOTICE([CURL Bin path $CURL_BIN])
     AC_SUBST(LIBCURL_CPPFLAGS)
     AC_SUBST(LIBCURL)
     AC_DEFINE_UNQUOTED(
	[LIBCURL_BINARY],
	["$CURL_BIN"],
	[curl binary path]
     )


     AC_SUBST(CURL_BIN)

])
