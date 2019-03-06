#define G_LOG_DOMAIN "keyagent-tests"

#include <glib.h>
#include <libgen.h>
#include <stdlib.h>
#include "key-agent/key_agent.h"
#include "config.h"


/**
[core]
npm-directory=/tmp/key-server/npms
npm-list=reference,kmip
[reference]
url=http://localhost:8000
module=libnpm_reference.so
[kmip]
url=http://localhost:9000
module=libnpm_kmip.so
*/

const char *programname;
GString *testdir = NULL;

typedef struct {
	void *cfile;
	GString *filename;
} MyTestFixture;

static GString *
generate_testfile_name(const char *name)
{
	GString *testfile = g_string_new(testdir->str);
	testfile = g_string_append(testfile, name);
	return testfile;
}

static void
my_object_fixture_set_up (MyTestFixture *fixture,
                          gconstpointer user_data)
{
	g_autoptr(GError) err = NULL;
	fixture->filename = generate_testfile_name((const char *)user_data);
  	//fixture->cfile = key_config_openfile(fixture->filename->str, &err);
}

static void
my_object_fixture_tear_down (MyTestFixture *fixture,
                             gconstpointer user_data)
{
}

gboolean fatal_handler(const gchar *log_domain,
                      GLogLevelFlags log_level,
                      const gchar *message,
                      gpointer user_data)
{
	//g_print("%s - %s %s\n", __func__, log_domain, message);
	return FALSE;
}
 
void test_init(void)
{
	g_autoptr(GError) err = NULL;
	GString *filename = generate_testfile_name("key-agent.ini");
	g_test_log_set_fatal_handler (fatal_handler, NULL);
	g_assert_true(keyagent_init(filename->str, &err));
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

    g_test_init(&argc, &argv, NULL, "no_g_set_prgname", NULL);

  	g_option_context_add_main_entries (context, entries, "keyagent");
  	if (!g_option_context_parse (context, &argc, &argv, &error))
    {
      g_print ("option parsing failed: %s\n", error->message);
      exit (1);
    }

    GLogLevelFlags fatal_mask = (GLogLevelFlags) g_log_set_always_fatal ((GLogLevelFlags) (G_LOG_FATAL_MASK & ~G_LOG_LEVEL_WARNING));

	if (!testdir) {
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "PATH-3:%s", DHSM2_CONF_PATH); //dirname((char *)programname));
		set_testdir(NULL,DHSM2_CONF_PATH, NULL, NULL);
	}
    g_test_add_func("/key_agent/test_init", test_init);

    return g_test_run();
}
