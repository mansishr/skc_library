#define G_LOG_DOMAIN "keyagent-init"
#include "k_errors.h"
#include "internal.h"
#include "config-file/key_configfile.h"

local_key_agent key_agent;

static void
initialize_npm(gpointer key, gpointer data, gpointer user_data)
{
	local_npm *npm = (local_npm *)data;
	GError **err = user_data;
	g_autoptr(GString) filename = NULL;
	if (!g_path_is_absolute (npm->module_name->str))
		filename = g_string_new(g_module_build_path(key_agent.npm_directory, npm->module_name->str));
	else
		filename = g_string_new(npm->module_name->str);

	npm_init_func  init_func;

	g_autoptr(GError) tmp_error = NULL;

	npm->module = g_module_open (filename->str, G_MODULE_BIND_LAZY);
	if (!npm->module)
	{
		k_set_error (&tmp_error, KEYAGENT_ERROR_NPMLOAD,
			"%s", g_module_error ());
		goto errexit;
	}
	if (!g_module_symbol (npm->module, "npm_init", (gpointer *)&init_func))
    {
		k_set_error (&tmp_error, KEYAGENT_ERROR_NPMLOAD,
                   "%s: %s", filename->str, g_module_error ());
		goto errexit;
    }
	init_func(&npm->npm,&tmp_error);
	if (tmp_error == NULL)
		npm->initialized = 1;
	return;
errexit:
	if (npm->module && !g_module_close (npm->module))
        	k_critical_msg ("%s: %s", filename, g_module_error ());

	npm->module = NULL;
	//g_propagate_error (err, tmp_error);
	k_debug_msg ("Error loading npm - %s: %s", npm->npm.name->str, tmp_error->message);
	return;
}


gboolean 
key_agent_init(const char *filename, GError **err)
{
    k_debug_msg("file - %s\n", filename);
	void *config = key_config_openfile(filename, err);
	if (*err != NULL)
	{
        k_debug_msg ("Error loading key file: %s %p", (*err)->message, config);
		return FALSE;
	}
    key_agent.npm_directory = key_config_get_string(config, "core", "npm-directory", err);
	if (*err != NULL) {
		return FALSE;
	}
    char **npms = key_config_get_string_list(config, "core", "npm-list", err);
	if (*err != NULL) {
		return FALSE;
	}

	key_agent.npm_hash = g_hash_table_new (g_str_hash, g_str_equal);
	key_agent.stm_hash = g_hash_table_new (g_str_hash, g_str_equal);

	while (*npms) 
	{
		local_npm *npm = g_new0(local_npm, 1);
		npm->key_queue = g_queue_new();
		npm->npm.name = g_string_new(*npms);
		npm->npm.url = g_string_new(key_config_get_string(config, *npms, "url", err)); 
		npm->module_name = g_string_new(key_config_get_string(config, *npms, "module", err)); 
		g_hash_table_insert(key_agent.npm_hash, npm->npm.name->str, npm);
		++npms;
	}
	g_hash_table_foreach(key_agent.npm_hash, initialize_npm, err);

    key_agent.key_directory = key_config_get_string(config, "core", "key-directory", err);
	if (*err != NULL) {
		return FALSE;
	}
	load_keys(err);
	return TRUE;
}

static void
show_npms(gpointer key, gpointer data, gpointer user_data)
{
	local_npm *npm = (local_npm *)data;
	g_print("NPM - %s (%s) - %s -%s\n", npm->npm.name->str, 
		(npm->initialized ? "Initialized" : "Failed"),
		npm->npm.url->str, npm->module_name->str);
}
          
void
key_agent_listnpms()
{
	g_print("\n");
	g_hash_table_foreach(key_agent.npm_hash, show_npms, NULL);
}

static void
show_stms(gpointer key, gpointer data, gpointer user_data)
{
	local_stm *stm = (local_stm *)data;
	g_print("STM - %s (%s) - %s\n", stm->stm.name->str, 
		(stm->initialized ? "Initialized" : "Failed"),
		stm->module_name->str);
}
          
void
key_agent_liststms()
{
	g_print("\n");
	g_hash_table_foreach(key_agent.stm_hash, show_stms, NULL);
}

