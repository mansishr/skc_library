AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(GMODULE_CFLAGS)

bin_PROGRAMS = \
   keyagent-cli

keyagent_cli_SOURCES = \
    main.c

keyagent_cli_LDFLAGS =  -ljsoncpp
keyagent_cli_LDADD = $(top_srcdir)/../key-agent/src/libkey_agent.la
