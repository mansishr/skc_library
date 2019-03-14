AM_CPPFLAGS = -g -I../../../key-agent/ $(COMMON_FLAGS) $(GMODULE_CFLAGS) $(OPENSSL_INCLUDES)

bin_PROGRAMS = \
   npm_tapp

npm_tapp_SOURCES = \
    test_app.c

npm_tapp_LDFLAGS = -ljsoncpp $(OPENSSL_LIBS)
npm_tapp_LDADD = ../../../key-agent/src/libkey_agent.la
