#define G_LOG_DOMAIN "keyagent-cli"

#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include "key-agent/types.h"
#include "key-agent/key_agent.h"

#include <syslog.h>
#include "k_errors.h"
#include "config.h"


const gchar g_log_domain[] = "keyagent-cli";
static gboolean verbose = FALSE;
static gboolean listnpms = FALSE;
static gboolean liststms = FALSE;
static gboolean debug = FALSE;
static gchar *configfile = NULL;
static gchar *keyurl = NULL;

static GOptionEntry entries[] =
{
  { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Be verbose", NULL },
  { "config", 0, 0, G_OPTION_ARG_FILENAME, &configfile, "required! config file to use", NULL },
  { "list-npms", 0, 0, G_OPTION_ARG_NONE, &listnpms, "List the npms", NULL },
  { "list-stms", 0, 0, G_OPTION_ARG_NONE, &liststms, "List the stms", NULL },
  { "load-key", 0, 0, G_OPTION_ARG_FILENAME, &keyurl, "url of key to transfer", NULL },
  { "debug", 0, 0, G_OPTION_ARG_NONE, &debug, "enable debug output", NULL },
  { NULL }
};

static gboolean
apimodule_set_wrapping_key(keyagent_apimodule_session_details *details, void *extra, GError **err)
{
	return TRUE;
}

static gboolean
apimodule_load_key(keyagent_apimodule_loadkey_details *details, void *extra, GError **err)
{
	return TRUE;
}

static gboolean
apimodule_get_challenge(keyagent_apimodule_get_challenge_details *details, void *request, GError **err)
{
	return TRUE;
}

int
main (int argc, char *argv[])
{
	GError *error = NULL;
	GOptionContext *context;
   	keyagent_apimodule_ops apimodule_ops;
   	memset(&apimodule_ops, 0, sizeof(apimodule_ops));

	context = g_option_context_new ("- key-agent cli");
	g_option_context_add_main_entries (context, entries, NULL);
	if (!g_option_context_parse (context, &argc, &argv, &error))
	{
		g_print ("option parsing failed: %s\n", error->message);
		exit (1);
	}

	if (debug) { 
		setenv("G_MESSAGES_DEBUG", "all", 1);
	}

	//g_log_set_writer_func (log_writer, NULL, NULL);

	k_debug_msg("TESTING");
	if (!configfile)
	{
		configfile = g_strconcat (DHSM2_CONF_PATH,"/key-agent.ini", NULL);
	}
	if (!keyagent_init(configfile, &error))
	{
		k_fatal_error(error);
		exit(1);
	}
	if (listnpms)
		keyagent_npm_showlist();

	if (liststms)
		keyagent_stm_showlist();


	if (keyurl)
    	apimodule_ops.load_key = apimodule_load_key;
    	apimodule_ops.get_challenge = apimodule_get_challenge;
    	apimodule_ops.set_wrapping_key = apimodule_set_wrapping_key;
    	if (!keyagent_apimodule_register(NULL, &apimodule_ops, &error)) {
        	k_critical_msg(error->message);
        	return FALSE;
    	}
    	k_debug_msg("keyagent_apimodule_register is successful !!!");

		if (!keyagent_loadkey(keyurl, &error))
            k_info_error(error);

	g_free(configfile);

	exit(0);
}
