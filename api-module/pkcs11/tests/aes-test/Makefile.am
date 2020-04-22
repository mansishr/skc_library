AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(GMODULE_CFLAGS) $(OPENSSL_INCLUDES) -std=c++11 `pkg-config --cflags p11-kit-1` 

noinst_PROGRAMS = \
   aes_encrypt_decrypt

aes_encrypt_decrypt_SOURCES = \
   aes_encrypt_decrypt.cpp

aes_encrypt_decrypt_LDFLAGS =  $(GLIB_LIBS) $(GMODULE_LIBS)
