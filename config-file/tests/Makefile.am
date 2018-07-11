include $(top_srcdir)/glib-tap.mk

test_programs = \
   test_configfile \
   test_configfile1

AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS)

test_configfile_SOURCES = \
    configtest.c

test_configfile_LDFLAGS = 
test_configfile_LDADD = ../src/libkey_configfile.la

test_configfile1_SOURCES = \
    configtest1.c

test_configfile1_LDFLAGS = 
test_configfile1_LDADD = ../src/libkey_configfile.la


