include $(top_srcdir)/glib-tap.mk

test_programs = \
   test_configfile \
   test_errors

AM_CPPFLAGS = -I$(top_srcdir)/$(COMMON_FLAGS)

test_configfile_SOURCES = \
    configtest.c

test_configfile_LDFLAGS = 
test_configfile_LDADD = $(top_srcdir)/key-agent/src/libkey_agent.la

test_errors_LDFLAGS = 
test_errors_LDADD = $(top_srcdir)/key-agent/src/libkey_agent.la
