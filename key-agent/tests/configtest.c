#define G_LOG_DOMAIN "keyagent-tests"

#include <glib.h>
#include <libgen.h>
#include <stdlib.h>
#include "key-agent/key_agent.h"


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
	keyagent_npm_showlist();
}

static void
test_vals (MyTestFixture *fixture,
                      gconstpointer user_data)
{
	char *strval;
	int intval;
	g_assert_nonnull(fixture->cfile);
	g_autoptr(GError) err = NULL;

/*
	g_assert_nonnull(key_config_get_value(fixture->cfile, "section1", "name1", &err));
	g_assert_null(err);
	g_assert_null(key_config_get_value(fixture->cfile, "section1", "name1x", &err));
	g_assert_nonnull(err);
	g_clear_error(&err);
	g_assert_cmpstr(key_config_get_value_optional(fixture->cfile, "section1", "name1x", "defaulttest1"), ==,  "defaulttest1");
	g_assert_cmpint(key_config_get_integer(fixture->cfile, "section2", "Val2", &err), ==,  19);
	g_assert_null(err);
	g_assert_cmpint(key_config_get_integer_optional(fixture->cfile, "section2", "Val2", 0), ==,  19);
	g_assert_cmpint(key_config_get_integer_optional(fixture->cfile, "section2", "Foo", 23), ==,  23);
*/
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
	if (!testdir) {
		set_testdir(NULL,dirname((char *)programname), NULL, NULL);
	}

    g_test_add_func("/key_agent/test_init", test_init);

/*
  	g_test_add ("/key_agent/test_vals", MyTestFixture, "key-agent.ini",
              my_object_fixture_set_up, test_vals,
              my_object_fixture_tear_down);
*/
    return g_test_run();
}
