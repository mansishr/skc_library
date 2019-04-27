source config
CFLAGS="`pkg-config --cflags glib-2.0` -I${INSTALLDIR}/include"
LDFLAGS="`pkg-config --libs glib-2.0 gmodule-2.0`"

g++ -o aes_encrypt_decrypt aes_encrypt_decrypt.cpp $CFLAGS $LDFLAGS

