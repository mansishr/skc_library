#include <stdio.h>
#include <gmodule.h>
#include <glib.h>
#include <string.h>
#include <unistd.h>
#include "k_errors.h"
#include "key-agent/src/internal.h"
#include "key-agent/types.h"

/*using namespace keyagent;*/

const char *programname						= NULL;
const char *module_path						= "./../src/.libs/npm_kms.so";
GString *testdir							= NULL;
GError *error								= NULL;


typedef struct user_data
{
	GString			*filename;
	GString			*npm_module_str;
	GError			**error;
}USER_DATA;


typedef struct mytestfixture {
	USER_DATA		*user_data;
	keyagent_npm_real npm;
} MyTestFixture;


char cwd[100];

static void* load_fixture_data(MyTestFixture *conf, GError **error)
{
    const char *filename					= (const char *)conf->user_data->filename->str;
	conf->npm.key_queue						= g_queue_new();
	conf->npm.module_name					= g_string_new(conf->user_data->npm_module_str->str);
	
	k_debug_msg("Module name:%s, current dir:%s\n", conf->npm.module_name->str, getcwd(cwd, sizeof(cwd)));
	g_autoptr(GError) tmp_error				= NULL;
	conf->npm.module						= g_module_open (conf->npm.module_name->str, G_MODULE_BIND_LAZY);
	if (!conf->npm.module)
	{
		k_debug_msg("Error in module open\n");
		return NULL;
	}

	keyagent_npm_real *npm					= (keyagent_npm_real *)&conf->npm;
    LOOKUP_NPM_INTERFACES(npm, KEYAGENT_ERROR_NPMLOAD);
	k_debug_msg("Module load is successful\n");
	return conf->npm.module;
errexit:
	if( conf->npm.module)
	{
		g_module_close(conf->npm.module);
		return NULL;
	}
	return NULL;
}

static void fsetup (MyTestFixture *fixture, gconstpointer user_data)
{
	k_debug_msg("Calling %s\n", __func__);
	g_autoptr(GError) error					= NULL;
	fixture->user_data						= (USER_DATA *)user_data;
	load_fixture_data(fixture, &error);
}

static void fteardown (MyTestFixture *fixture, gconstpointer user_data)
{
	k_debug_msg("Calling %s\n", __func__);
	g_module_close(fixture->npm.module);
}
static void ftest_load_module(MyTestFixture *fixture, gconstpointer user_data)
{
	/*k_debug_msg("Calling %s:%p\n", __func__, fixture->npm_init);*/
	g_assert_nonnull(fixture->npm.module);
	g_assert_nonnull(fixture->npm.ops.npm_func_init);
	g_assert_nonnull(fixture->npm.ops.npm_func_register);
	g_assert_nonnull(fixture->npm.ops.npm_func_key_load);
	g_assert_nonnull(fixture->npm.ops.npm_func_finalize);
}

gboolean fatal_handler(const gchar *log_domain,
                      GLogLevelFlags log_level,
                      const gchar *message,
                      gpointer user_data)
{
	return FALSE;
}
static void ftest_init_npm(MyTestFixture *fixture, gconstpointer user_data)
{
	k_debug_msg("Calling %s:%p\n", __func__, fixture->npm.ops.npm_func_init);

	g_autoptr(GError) tmp_error				= NULL;
	USER_DATA *udata				   		= (USER_DATA *)user_data;
	keyagent_npm_real *npm					= (keyagent_npm_real *)&fixture->npm;
	void *init_func							= NPM_MODULE_OP(npm, init);

	g_assert_nonnull(npm);
	g_assert_nonnull(init_func);
	g_test_log_set_fatal_handler (fatal_handler, NULL);
	g_assert_null(NPM_MODULE_OP(npm, init)("./config", &tmp_error));

	g_autoptr(GError) tmp_error1			= NULL;
	g_assert_null(NPM_MODULE_OP(npm, init)("./", &tmp_error1));
	if(tmp_error1)
	{
		k_debug_msg("Error:%s\n", tmp_error1->message);
	}

	/*g_autoptr(GError) tmp_error1			= NULL;*/
	/*g_assert_cmpstr(NPM_MODULE_OP(npm, init)("./", &tmp_error1), ==, "KMS");*/

	/*g_autoptr(GError) tmp_error2			= NULL;*/
	/*g_assert_null(NPM_MODULE_OP(npm, init)("./", &tmp_error2));*/
	/*if(tmp_error2)*/
	/*{*/
	/*k_debug_msg("Error:%s\n", tmp_error2->message);*/
	/*}*/
	g_assert_null(NPM_MODULE_OP(npm, init)(NULL, NULL));
	/*g_assert_null(NPM_MODULE_OP(npm, init)(NULL, &tmp_error));*/
}


static void ftest_register_npm(MyTestFixture *fixture, gconstpointer user_data)
{
	k_debug_msg("Calling %s:%p\n", __func__, fixture->npm.ops.npm_func_register);

	g_autoptr(GError) tmp_error				= NULL;
	USER_DATA *udata				   		= (USER_DATA *)user_data;
	keyagent_npm_real *npm					= (keyagent_npm_real *)&fixture->npm;

	g_assert_nonnull(npm);
	g_assert_nonnull(NPM_MODULE_OP(npm, register));
	g_test_log_set_fatal_handler (fatal_handler, NULL);
	g_assert_cmpint(NPM_MODULE_OP(npm, register)("./", &tmp_error), ==, TRUE);
	g_assert_null(NPM_MODULE_OP(npm, register)(NULL, NULL));
	/*g_assert_null(NPM_MODULE_OP(npm, register)(NULL, &tmp_error));*/
}

static void ftest_npm_load_key(MyTestFixture *fixture, gconstpointer user_data)
{
	/*k_debug_msg("Calling %s:%p\n", __func__, fixture->npm.ops.npm_func_register);*/

	g_autoptr(GError) tmp_error				= NULL;
	USER_DATA *udata				   		= (USER_DATA *)user_data;
	keyagent_npm_real *npm					= (keyagent_npm_real *)&fixture->npm;

	g_assert_nonnull(npm);
	g_assert_nonnull(NPM_MODULE_OP(npm, key_load));
	g_test_log_set_fatal_handler (fatal_handler, NULL);
	/*g_assert_cmpint(NPM_MODULE_OP(npm, key_load)("./", &tmp_error), ==, TRUE);*/
	g_assert_null(NPM_MODULE_OP(npm, key_load)(NULL, NULL));
	g_assert_null(NPM_MODULE_OP(npm, key_load)(NULL, &tmp_error));
}
void fill_userdata( USER_DATA *data, const char *module_path, char *conf_file_path)
{
	data->npm_module_str					= g_string_new(module_path);
	data->filename							= g_string_new(conf_file_path);
}

gboolean set_testdir(const gchar *option_name,
                   const gchar *value,
                   gpointer data,
                   GError **error)
{
    testdir									= g_string_new(value);
    testdir									= g_string_append(testdir, "/");
}

static GOptionEntry entries[]				=
{
  { "testdir", 'D', 0, G_OPTION_ARG_CALLBACK, set_testdir, "Directory where test files are", NULL},
  { NULL }
};

int main(int argc, char *argv[])
{

  	GOptionContext *context					= NULL;
	USER_DATA user_data						= { NULL, NULL};
	g_autoptr(GError) error					= NULL;

	setenv("G_MESSAGES_DEBUG", "all", 1);

    GLogLevelFlags fatal_mask = (GLogLevelFlags) g_log_set_always_fatal ((GLogLevelFlags) (G_LOG_FATAL_MASK & ~G_LOG_LEVEL_WARNING));
	programname								= argv[0];
  	context									= g_option_context_new ("- test tree model performance");

  	g_option_context_add_main_entries (context, entries, "configfile");
  	g_option_context_parse (context, &argc, &argv, &error);

 	g_test_init(&argc, &argv, NULL);
	g_test_set_nonfatal_assertions ();
	fill_userdata(&user_data, module_path, NULL);
	g_test_add("/npm/kms/tests/load_module", MyTestFixture, &user_data, fsetup, ftest_load_module, fteardown);
	g_test_add("/npm/kms/tests/npm_init", MyTestFixture, &user_data, fsetup, ftest_init_npm, fteardown);
	g_test_add("/npm/kms/tests/npm_register", MyTestFixture, &user_data, fsetup, ftest_register_npm, fteardown);
	g_test_add("/npm/kms/tests/npm_load_key", MyTestFixture, &user_data, fsetup, ftest_npm_load_key, fteardown);
	return g_test_run();
}
