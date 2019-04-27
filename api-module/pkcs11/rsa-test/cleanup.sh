set -x
. ./config

if [ "x$SOFTHSM_UTIL" != "x" ]
then
	serial=`$SOFTHSM_UTIL --show-slots | grep -i serial | cut -d: -f2 | tr -d [:blank:]`
	$SOFTHSM_UTIL --delete-token  --serial $serial
	rm -rf /var/lib/softhsm/tokens/*
fi

if [ "x$TOOLKIT_INSTALLDIR" != "x" ]
then
	rm -fr $TOOLKIT_INSTALLDIR/tokens/*
fi

rm -fr core*
