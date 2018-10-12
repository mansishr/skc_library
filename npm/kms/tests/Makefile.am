include $(top_srcdir)/glib-tap.mk

test_programs = \
   test_kms_npm 

AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS) $(GMODULE_CFLAGS) 

test_kms_npm_SOURCES = \
    test_npm_kms.c


test_kms_npm_LDFLAGS = 
test_kms_npm_LDADD = $(top_srcdir)/../../key-agent/src/libkey_agent.la
