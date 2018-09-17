
include $(top_srcdir)/glib-tap.mk

test_programs = \
   test_configfile \
   test_errors

AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(GMODULE_CFLAGS) -std=c++11

test_configfile_SOURCES = \
    configtest.c

test_configfile_LDFLAGS = 
test_configfile_LDADD = $(top_srcdir)/src/libkey_agent.la

test_errors_LDFLAGS = 
test_errors_LDADD = $(top_srcdir)/src/libkey_agent.la
