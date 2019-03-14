AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(GMODULE_CFLAGS)$(OPENSSL_INCLUDES) 

bin_PROGRAMS = \
   keyagent_testapp

keyagent_testapp_SOURCES = \
    test_app.c

keyagent_testapp_LDFLAGS =  -ljsoncpp $(OPENSSL_LIBS)
keyagent_testapp_LDADD = $(top_srcdir)/../key-agent/src/libkey_agent.la
