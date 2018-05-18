#define G_LOG_DOMAIN "keyagent-errors"
#include <k_errors.h>
#include <glib.h>
#include <libgen.h>
#include <stdlib.h>
#include "key-agent/key_agent.h"

const char *programname;
GString *testdir = NULL;

gboolean set_testdir(const gchar *option_name,
                   const gchar *value,
                   gpointer data,
                   GError **error)
{
		testdir = g_string_new(value);
		testdir = g_string_append(testdir, "/");
}

static GOptionEntry entries[] =
{
  { "testdir", 'D', 0, G_OPTION_ARG_CALLBACK, set_testdir, "Directory where test files are", NULL},
  { NULL }
};
 
int main(int argc, char** argv)
{
	programname = argv[0];

	g_autoptr(GError) error = NULL;

	K_LOG_TRACE();
	k_set_domain_error(&error, K_LOG_DOMAIN_ERROR, 
                   4,            // error code
                   "Failed to open file: %s", // error message format string
                   	g_strerror (4));

	k_critical_error(error); 
	k_critical_msg("this is test msg");

	k_set_error(&error, 5, "foo is it %d", 77);

	k_info_error(error); 
	k_info_msg("this is a info msg"); 
	k_debug_error(error); 
	k_debug_msg("this is a debug msg %d", 1);
	K_LOG_TRACE();
	k_fatal_error(error); 
	k_fatal_msg("this is a fatal msg %d", -1);
	
}
