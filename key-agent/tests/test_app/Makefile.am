AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(GMODULE_CFLAGS) 

bin_PROGRAMS = \
   keyagent_testapp

keyagent_testapp_SOURCES = \
    test_app.c

keyagent_testapp_LDFLAGS =  -ljsoncpp -lcrypto
keyagent_testapp_LDADD = $(top_srcdir)/../key-agent/src/libkey_agent.la
