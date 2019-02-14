#include <stdio.h>
#include <stdio.h>
#include <gmodule.h>
#include <glib.h>
#include <string.h>
#include <unistd.h>
#include "k_errors.h"
#include "key-agent/src/internal.h"
#include "key-agent/types.h"
#include "key-agent/npm/npm.h"
#include "key-agent/key_agent.h"

static gboolean verbose		= FALSE;
static gboolean debug 		= FALSE;
static gchar *npm_config_dir 	= NULL;
static gchar *key_agent_config	= NULL;
static gchar *npm_module	= NULL;
static gchar *keyurl 		= NULL;
static gchar *key_server	= NULL;

static GOptionEntry entries[] =
{
  { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Be verbose", NULL },
  { "npm_config_dir", 0, 0, G_OPTION_ARG_FILENAME, &npm_config_dir, "required! NPM config dir to use", NULL },
  { "npm_module", 0, 0, G_OPTION_ARG_FILENAME, &npm_module, "required! NPM module file to use", NULL },
  { "keyagent_config", 0, 0, G_OPTION_ARG_FILENAME, &key_agent_config, "required! key agent config file to use", NULL },
  { "key_url", 0, 0, G_OPTION_ARG_STRING, &keyurl, "key url to use input", NULL },
  { "key_server", 0, 0, G_OPTION_ARG_STRING, &key_server, "key server name", NULL },
  { "debug", 0, 0, G_OPTION_ARG_NONE, &debug, "enable debug output", NULL },
  { NULL }
};

typedef struct{
	GString			*module_path;
	GString			*module_name;
	GError			*error;
	keyagent_npm_real npm;

}module_info;

module_info module;

void* load_npm_module(module_info *conf)
{

	g_autoptr(GError) tmp_error				= NULL;
	conf->npm.module				        = g_module_open (conf->module_path->str, G_MODULE_BIND_LAZY);
    g_assert_nonnull(conf->npm.module);
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
}

gboolean fatal_handler(const gchar *log_domain,
                      GLogLevelFlags log_level,
                      const gchar *message,
                      gpointer user_data)
{
        return FALSE;
}
	
static void init_npm(module_info *fixture, gconstpointer user_data)
{
    g_autoptr(GError) tmp_error                             = NULL;
    g_autoptr(GError) tmp_error1                            = NULL;
    g_autoptr(GError) tmp_error2                            = NULL;
    g_autoptr(GError) error                                 = NULL;
    module_info *minfo                                      = (module_info *)user_data;
    keyagent_npm_real *npm                                  = (keyagent_npm_real *)&minfo->npm;
	g_assert_cmpint(keyagent_init(key_agent_config, &error),==,TRUE);
    void *init_func                                         = NPM_MODULE_OP(npm, init);
    g_assert_nonnull(npm);
    g_assert_nonnull(init_func);
    g_test_log_set_fatal_handler (fatal_handler, NULL);

	/*Test case 1: With invalide configuration file PATH*/
	g_assert_null(NPM_MODULE_OP(npm, init)("./config", &tmp_error));

	/*Test case 2: With configuration file PATH as NULL*/
	g_assert_null(NPM_MODULE_OP(npm, init)(NULL, &tmp_error1));

	/*Test case 3: With valide configuration file PATH*/
	g_assert_cmpstr(NPM_MODULE_OP(npm, init)(npm_config_dir, &tmp_error2), ==, key_server);

}

static void register_npm(module_info *fixture, gconstpointer user_data)
{
    g_autoptr(GError) tmp_error                             = NULL;
    g_autoptr(GError) tmp_error1                            = NULL;
    g_autoptr(GError) tmp_error2                            = NULL;
    g_autoptr(GError) tmp_error3                            = NULL;
    module_info *minfo                                      = (module_info *)user_data;
    keyagent_npm_real *npm                                  = (keyagent_npm_real *)&minfo->npm;

    g_assert_nonnull(npm);
    g_assert_nonnull(NPM_MODULE_OP(npm, register));
    g_test_log_set_fatal_handler (fatal_handler, NULL);

	/*Test case 1: With valide register and key URL*/
	g_assert_cmpint(NPM_MODULE_OP(npm, register)(keyurl, &tmp_error), ==, TRUE);

	/*Test case 2: With invalide register and valide key URL*/
	g_assert_cmpint(NPM_MODULE_OP(npm, register)("TEST:a67a6747-bd53-4280-90e0-5d310ba5fed9", &tmp_error1), ==, FALSE);

	/*Test case 3: With valide register URL and invalide key URL*/
	g_assert_cmpint(NPM_MODULE_OP(npm, register)("KMS:", &tmp_error2), ==, FALSE);

	/*Test case 4: With register URL and invalide key URL as NULL*/
	g_assert_cmpint(NPM_MODULE_OP(npm, register)("NULL", &tmp_error3), ==, FALSE);
}

static void npm_load_key(module_info *fixture, gconstpointer user_data)
{
	g_autoptr(GError) tmp_error				= NULL;
	g_autoptr(GError) tmp_error1			= NULL;
	g_autoptr(GError) tmp_error2			= NULL;
	g_autoptr(GError) tmp_error3			= NULL;
    module_info *minfo                      = (module_info *)user_data;
	keyagent_npm_real *npm					= (keyagent_npm_real *)&minfo->npm;
	g_assert_nonnull(npm);
	g_assert_nonnull(NPM_MODULE_OP(npm, key_load));
	g_test_log_set_fatal_handler (fatal_handler, NULL);

	/*Test case 1: With valide register URL and key URL*/
	g_assert_null(keyagent_loadkey(keyurl, &tmp_error));

	/*Test case 2: With valide register URL and new key URL*/
	/*g_assert_cmpint(keyagent_loadkey("KMS:a67a6747-bd53-4280-90e0-5d310ba5fed8", &tmp_error2), ==, TRUE);*/

	/*Test case 3: With invalide URL as NULL*/
	g_assert_cmpint(NPM_MODULE_OP(npm, key_load)(NULL, &tmp_error3), ==, FALSE);

	/*Test case 4: With invalide register URL and invalide key URL*/
	g_assert_nonnull(keyagent_loadkey("TEST:a67a6747-bd53-4280-90e0-5d310ba5fe", NULL));
}

void fill_userdata( module_info *data, const char *module_path, char *conf_file_path)
{
    data->module_path                                    = g_string_new(module_path);
    data->module_name                                    = g_string_new(npm_module);
}

static void fsetup (module_info *fixture, gconstpointer user_data)
{
	g_log_set_always_fatal ((GLogLevelFlags) (G_LOG_FATAL_MASK & ~G_LOG_LEVEL_CRITICAL));
	g_test_log_set_fatal_handler (fatal_handler, NULL);
	g_test_set_nonfatal_assertions ();
	module_info *module_data = (module_info *)user_data;
	g_autoptr(GError) error                                 = NULL;
    load_npm_module(module_data);
}

static void fteardown (module_info *fixture, gconstpointer user_data)
{
	module_info *module_data = (module_info *)user_data;
    g_module_close(module_data->npm.module);
}

int main(int argc, char *argv[])
{
	GError *error = NULL;
	GOptionContext *context;

	context = g_option_context_new ("- kms-npm cli");
	g_option_context_add_main_entries (context, entries, NULL);
	if (!g_option_context_parse (context, &argc, &argv, &error))
	{
		g_print ("option parsing failed: %s\n", error->message);
		exit (1);
	}

	if (debug) { 
		setenv("G_MESSAGES_DEBUG", "all", 1);
	}
	if (!npm_module)
	{
		g_print ( "Invalid npm_module \n", argv[0]);
		exit (1);
	}
	if( !key_agent_config)
	{
		key_agent_config = g_strconcat (DHSM2_CONF_PATH,"/key-agent.ini", NULL);
	}

	if( !key_server)
	{
		g_print ( "Invalid keyserver \n", argv[0]);
	    exit (1);
	}

	if( !keyurl)
	{
		g_print ( "Invalid keyurl \n", argv[0]);
	    exit (1);
	}
	npm_config_dir=g_strconcat(DHSM2_INSTALL_DIR,"/etc/", NULL);

	g_autoptr(GError) tmp_error;
	memset (&module, 0x00, sizeof(module_info));
	module.error=tmp_error;

	g_test_init(&argc, &argv, NULL);
	fill_userdata(&module,(const char * )npm_module , NULL);
    g_test_add("/npm_test_app/npm_init", module_info, &module, fsetup, init_npm, fteardown);
    g_test_add("/npm_test_app/npm_register", module_info, &module, fsetup, register_npm, fteardown);
    g_test_add("/npm_test_app/npm_load_key", module_info, &module, fsetup, npm_load_key, fteardown);

	return g_test_run();
}
