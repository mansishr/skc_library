include ../glib-tap.mk

test_programs = \
   test_configfile

AM_CPPFLAGS = -I$(top_srcdir) $(COMMON_FLAGS)

test_configfile_SOURCES = \
    configtest.c

test_configfile_LDFLAGS = 
test_configfile_LDADD = ../src/libkey_configfile.la
