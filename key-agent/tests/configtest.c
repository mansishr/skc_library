#define G_LOG_DOMAIN "keyagent-tests"

#include <glib.h>
#include <libgen.h>
#include <stdlib.h>
#include "key-agent/key_agent.h"
#include "config.h"


const char *programname;
GString *testdir = NULL;

typedef struct {
	gchar* configfile;
} testcase_data;

static GString *
generate_testfile_name(const char *name)
{
	GString *testfile = g_string_new(testdir->str);
	testfile = g_string_append(testfile, name);
	return testfile;
}

static void
fsetup (gpointer fixture,
                          gconstpointer user_data)
{
}

static void
fteardown(gpointer fixture,
                             gconstpointer user_data)
{
	testcase_data *d= (testcase_data *)user_data;
	if( d->configfile )
		g_free(d->configfile);
}

gboolean fatal_handler(const gchar *log_domain,
                      GLogLevelFlags log_level,
                      const gchar *message,
                      gpointer user_data)
{
	return FALSE;
}
 
void test_init(gpointer ptr, gpointer data)
{
	g_autoptr(GError) err = NULL;
	testcase_data *d= (testcase_data *)data;
	d->configfile = g_strconcat (DHSM2_CONF_PATH,"/key-agent.ini", NULL);
	g_test_log_set_fatal_handler (fatal_handler, NULL);
	g_assert_true(keyagent_init(d->configfile, &err));
	keyagent_npm_showlist();
}

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

  	GOptionContext *context;
	GError *error = NULL;
  	context = g_option_context_new ("- test keyagent");
	int i;

    g_test_init(&argc, &argv, NULL, "no_g_set_prgname", NULL);

  	g_option_context_add_main_entries (context, entries, "keyagent");
  	if (!g_option_context_parse (context, &argc, &argv, &error))
    {
      g_print ("option parsing failed: %s\n", error->message);
      exit (1);
    }


    GLogLevelFlags fatal_mask = (GLogLevelFlags) g_log_set_always_fatal ((GLogLevelFlags) (G_LOG_FATAL_MASK & ~G_LOG_LEVEL_WARNING));

	if (!testdir) {
        char *tmp = dirname(strdup(programname));
        char *tmp1 = basename(strdup(tmp));
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s", tmp); //dirname((char *)programname));
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s", tmp1); //dirname((char *)programname));
        if (!strcmp(basename(tmp), ".libs"))
            tmp = dirname(tmp);
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s", tmp); //dirname((char *)programname));
		set_testdir(NULL,tmp, NULL, NULL);
	}

    g_test_set_nonfatal_assertions ();
	testcase_data data={NULL};
	g_test_add("/key_agent/test_init", gpointer, &data, fsetup, test_init, fteardown);
    return g_test_run();
}
