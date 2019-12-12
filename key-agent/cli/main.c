#define G_LOG_DOMAIN "keyagent-cli"

#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <gmodule.h>
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
static gchar *api_module = NULL;
static gchar *keyurl = NULL;

static GOptionEntry entries[] =
{
  { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Be verbose", NULL },
  { "config", 0, 0, G_OPTION_ARG_FILENAME, &configfile, "required! config file to use", NULL },
  { "list-npms", 0, 0, G_OPTION_ARG_NONE, &listnpms, "List the npms", NULL },
  { "list-stms", 0, 0, G_OPTION_ARG_NONE, &liststms, "List the stms", NULL },
  { "load-key", 0, 0, G_OPTION_ARG_FILENAME, &keyurl, "url of key to transfer", NULL },
  { "api-module", 0, 0, G_OPTION_ARG_FILENAME, &api_module, "API Moduel path", NULL },
  { "debug", 0, 0, G_OPTION_ARG_NONE, &debug, "enable debug output", NULL },
  { NULL }
};

apimodule_initialize_func apimodule_initialize;

gboolean
load_apimodule(const char *module_name)
{
    GModule *mod = NULL;
    gboolean ret = FALSE;

    do {
        mod = g_module_open(module_name, G_MODULE_BIND_LOCAL);
        if (!mod) {
            k_critical_msg("%s: %s", module_name, g_module_error ());
            break;
        }
	if (!g_module_symbol(mod, "apimodule_initialize", (gpointer *)&apimodule_initialize)) {
            k_critical_msg("%s: apimodule_initialize func not found", module_name);
	    break;
	}

	ret=TRUE;
    } while (FALSE);
    return ret;
}


int
main (int argc, char *argv[])
{
	GError *error = NULL;
	GOptionContext *context;
   	keyagent_apimodule_ops apimodule_ops;

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
		configfile = g_strconcat (SKC_CONF_PATH,"/key-agent.ini", NULL);
	}
	if (!api_module && !keyurl && !keyagent_init(configfile, &error))
	{
		k_fatal_error(error);
		goto end;
	}
	if (listnpms)
		keyagent_npm_showlist();

	if (liststms)
		keyagent_stm_showlist();


	if (keyurl && api_module)
	{
	        k_debug_msg("Keyurl:%s, api_module:%s\n", keyurl, api_module);	
               	if( load_apimodule(api_module) == FALSE ){
			k_critical_msg("API module load is failed\n");
			goto end;	
		}
	         
                apimodule_initialize(&apimodule_ops, &error);	
		if( error != NULL)
		{
			k_critical_error(error);
			goto end;
		}
		if( apimodule_ops.load_uri != NULL && apimodule_ops.load_uri(keyurl) != TRUE )
		{
			k_critical_msg("API Module Load URI failed\n");
			goto end;
		}
		k_debug_msg("Key:%s successfully loaded in api_module:%s\n", keyurl, api_module);
		
	}else if ( keyurl && !api_module ){
		k_critical_msg("--api-module <api_module_path> missing\n");
		goto end;
	}


end:

	if(configfile)
		g_free(configfile);
	if(keyurl)
		g_free(keyurl);
	if(api_module)
		g_free(api_module);

	exit(0);
}
