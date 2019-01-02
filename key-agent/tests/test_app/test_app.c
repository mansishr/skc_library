#define G_LOG_DOMAIN "keyagent-testapp"

#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include "key-agent/key_agent.h"
#include "k_errors.h"
#include "config.h"

typedef struct conf_testcase_info
{
	gchar *file_buffer;
	gchar *attribute;
	gchar *replacement_string;
	gboolean expected_res;
	gchar *regex_buffer;
}ka_conf_tc_info;

static gboolean verbose	= FALSE;
static gboolean debug 	= FALSE;
static gchar *configfile= NULL;
static gchar *keyurl 	= NULL;
const gchar * tmp_configfile = "./tmp_ka_config.ini" ;

static GOptionEntry entries[] =
{
  { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Be verbose", NULL },
  { "key-url", 0, 0, G_OPTION_ARG_FILENAME, &keyurl, "url of key to transfer", NULL },
  { "debug", 0, 0, G_OPTION_ARG_NONE, &debug, "enable debug output", NULL },
  { NULL }
};

gboolean fatal_handler(const gchar *log_domain,
                      GLogLevelFlags log_level,
                      const gchar *message,
                      gpointer user_data)
{
        return FALSE;
}

static void keyagent_init_testcases()
{
	g_autoptr(GError) error	 = NULL;
	g_autoptr(GError) error1 = NULL;
	g_autoptr(GError) error2 = NULL;

	/*Test case 1 : With valid configuration path*/
	g_assert_cmpint(keyagent_init(configfile, &error),==,TRUE);

	/*Test case 2 : With invalid configuration path*/
	g_assert_cmpint(keyagent_init("./configs", &error1),==,FALSE);

	/*Test case 3 : configuration path as NULL*/
	g_assert_cmpint(keyagent_init(NULL, &error2),==,FALSE);

}

static void keyagent_loadkey_testcases()
{
	g_autoptr(GError) error  = NULL;
	g_autoptr(GError) error1 = NULL;
	g_autoptr(GError) error2 = NULL;
	g_autoptr(GError) error3 = NULL;
	g_autoptr(GError) error4 = NULL;

	/*Test case 1 : With valid kayurl*/
	g_assert_nonnull(keyagent_loadkey(keyurl, &error));

	/*Test case 2 : With invalid kayurl*/
	g_assert_null(keyagent_loadkey("TEST:a67a6747-bd53-4280-90e0-5d310ba5ff3d9", &error1));

	/*Test case 3 : With invalid kayurl*/
	g_assert_null(keyagent_loadkey("KMS:", &error2));

	/*Test case 4 :kayurl as NULL*/
	g_assert_null(keyagent_loadkey(NULL, &error3));

	/*Test case 5 : With invalid kayurl*/
	g_assert_null(keyagent_loadkey(":a67a6747-bd53-4280-90e0-5d310ba5ff3d9", &error4));
}

static void update_ka_conf_buffer (ka_conf_tc_info *input_data)
{
	GRegex *regex;

	regex = g_regex_new (input_data->attribute, 0, 0, NULL);
	input_data->regex_buffer = g_regex_replace (regex, input_data->file_buffer, -1, 0, input_data->replacement_string, 0, NULL);
	g_regex_unref (regex);
}
static void update_ka_conf(ka_conf_tc_info *input_data)
{
	g_autoptr(GError) error = NULL;
	gsize buffer_length ;
	
	/*Read content from file */
	g_file_get_contents (configfile, &input_data->file_buffer, &buffer_length, NULL); 

	/*Replace with content */
	update_ka_conf_buffer(input_data);

	/*write into file with configuration changes */
	g_file_set_contents (tmp_configfile, input_data->regex_buffer, buffer_length, NULL);

}

static void keyagent_config_testcase(gpointer *data,gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	ka_conf_tc_info *test_data = (ka_conf_tc_info *)user_data;
	update_ka_conf(test_data);
	
	g_assert_cmpint(keyagent_init(tmp_configfile, &error),==,test_data->expected_res);
}

static void keyagent_npm_list()
{
	keyagent_npm_showlist();
}

static void keyagent_stm_list()
{
	keyagent_stm_showlist();
}

static void fsetup ()
{
	g_test_log_set_fatal_handler (fatal_handler, NULL);
}

static void blackbox_tc_fteardown (gpointer *temp, gconstpointer user_data)
{
	/*Removing tmp_configfile and buffer memory */
	ka_conf_tc_info *test_data = (ka_conf_tc_info *)user_data;
	g_remove (tmp_configfile);
	g_free(test_data->file_buffer);

}

static void func_tc_fteardown ()
{
	return;
}
int
main (int argc, char *argv[])
{
	g_autoptr(GError) error = NULL;
	GOptionContext *context;

	context = g_option_context_new ("- key-agent testapp");
	g_option_context_add_main_entries (context, entries, NULL);
	if (!g_option_context_parse (context, &argc, &argv, &error))
	{
		g_print ("option parsing failed: %s\n", error->message);
		exit (1);
	}
	if (debug) {
		setenv("G_MESSAGES_DEBUG", "all", 1);
	}
	if (!configfile)
	{
		configfile = g_strconcat (DHSM2_CONF_PATH,"/key-agent.ini", NULL);
	}
	if (!keyurl)
	{
		keyurl = "KMS:a67a6747-bd53-4280-90e0-5d310ba5ff3d9";
	}
	g_test_init(&argc, &argv, NULL);
	g_test_set_nonfatal_assertions ();
	
	ka_conf_tc_info tc[]={    { NULL,"npm-directory.*","npm-directory=/tmp/dhsm2/lib/npm-modules",FALSE},
				  { NULL,"stm-directory.*","stm-directory=/tmp/dhsm2/lib/stm-modules",FALSE},
				  { NULL,"npm-list.*","npm-list=reference,TEST",FALSE},
				  { NULL,"key-directory.*","key-directory=/tmp/keys/",FALSE},
				  { NULL,"cert=.*","cert=/tmp/dhsm2/etc/server.crt" ,FALSE},
				  { NULL,"certkey.*","certkey=/tmp/dhsm2/etc/server.key",FALSE },
				  { NULL,"database_provider.*","database_provider=TEST" ,FALSE},
				  { NULL,"directory=.*","directory=/tmp/dhsm2/var/cache/keycache_cache1" ,FALSE},
				  { NULL,"cache_keys.*","cache_keys=true" ,TRUE},
				  { NULL,"cache_sessions.*","cache_sessions=true",TRUE}
			     };
	/*Funtionality test cases */
        g_test_add("/key-agent/test_app/keyagent_init", gpointer , NULL, fsetup, keyagent_init_testcases, func_tc_fteardown);
        g_test_add("/key-agent/test_app/keyagent_loadkey", gpointer , NULL, fsetup, keyagent_loadkey_testcases, func_tc_fteardown);
        g_test_add("/key-agent/test_app/keyagent_npm_list", gpointer , NULL, fsetup, keyagent_npm_list, func_tc_fteardown);
        g_test_add("/key-agent/test_app/keyagent_stm_list", gpointer , NULL, fsetup, keyagent_stm_list, func_tc_fteardown);
        
	/* Black Box test cases */
	g_test_add("/key-agent/test_app/keyagent_testcase_config_npm_dir", gpointer, &tc[0], fsetup, keyagent_config_testcase, blackbox_tc_fteardown);
        g_test_add("/key-agent/test_app/keyagent_testcase_config_stm_dir", gpointer ,&tc[1] , fsetup, keyagent_config_testcase, blackbox_tc_fteardown);
        g_test_add("/key-agent/test_app/keyagent_testcase_config_npm_list", gpointer ,&tc[2], fsetup, keyagent_config_testcase, blackbox_tc_fteardown);
        g_test_add("/key-agent/test_app/keyagent_testcase_config_key_dir",gpointer ,&tc[3] , fsetup, keyagent_config_testcase, blackbox_tc_fteardown);
        g_test_add("/key-agent/test_app/keyagent_testcase_config_cert_path", gpointer ,&tc[4], fsetup, keyagent_config_testcase, blackbox_tc_fteardown);
        g_test_add("/key-agent/test_app/keyagent_testcase_config_certkey_path", gpointer ,&tc[5], fsetup, keyagent_config_testcase, blackbox_tc_fteardown);
        g_test_add("/key-agent/test_app/keyagent_testcase_config_database_provider", gpointer ,&tc[6], fsetup, keyagent_config_testcase, blackbox_tc_fteardown);
        g_test_add("/key-agent/test_app/keyagent_testcase_config_cache_keys", gpointer ,&tc[8], fsetup, keyagent_config_testcase, blackbox_tc_fteardown);
        g_test_add("/key-agent/test_app/keyagent_testcase_config_cache_session", gpointer ,&tc[9], fsetup, keyagent_config_testcase, blackbox_tc_fteardown);
	
	return g_test_run();
}
