#define G_LOG_DOMAIN "keyagent-keyinit"
#include "k_errors.h"
#include "config-file/key_configfile.h"
#include "internal.h"
#include <glob.h>

static void
read_key_config(char *filename, GError **err)
{
	GError *tmp_err = NULL;
	void *config = key_config_openfile(filename, &tmp_err);
	if (tmp_err != NULL) 
	{
		goto errexit;
	}

	g_autoptr(GString) keyserver_label = g_string_new(key_config_get_string(config, "keyserver", "name", &tmp_err));
	if (tmp_err != NULL) 
	{
        g_prefix_error(&tmp_err,
                   "%s: keyserver label %s invalid.", filename, keyserver_label->str);
		goto errexit;
	}

	local_npm *npm = g_hash_table_lookup(key_agent.npm_hash, keyserver_label->str);
	if (!npm)
	{
        k_set_error (&tmp_err, KEYAGENT_ERROR_KEYCONF,
                   "%s: keyserver label %s invalid.", filename, keyserver_label->str);
		goto errexit;
	}

    npm_key_init_func  key_init_func;

    if (!g_module_symbol (npm->module, "npm_key_init", (gpointer *)&key_init_func))
    {
        k_set_error (&tmp_err, KEYAGENT_ERROR_NPMLOAD,
                   "%s: %s", filename, g_module_error ());
        goto errexit;
    }

	g_string_append_printf(keyserver_label, "-key-%d", g_queue_get_length(npm->key_queue));
	GQuark id = g_quark_from_string(keyserver_label->str);
    keyagent_npm_key *npm_key = key_init_func(&npm->npm,config, id, &tmp_err);
    if (tmp_err)
    {
        k_set_error (&tmp_err, KEYAGENT_ERROR_NPMKEYINIT,
                   "%s: %s", filename, g_module_error ());
        goto errexit;
	}

	g_queue_push_tail(npm->key_queue, npm_key);
	
errexit:
	if (config)
	{
		key_config_closefile(config);
	}
	if (tmp_err) 
	{
    	g_propagate_error (err, tmp_err);
	}
}

void
load_keys(GError **err)
{
	glob_t results;
	int i, ret;

	g_autoptr(GString) pattern = g_string_new(key_agent.key_directory);
	pattern = g_string_append(pattern,"*/config.ini");
	ret = glob(pattern->str, 0, NULL, &results);

	GError *tmp_err = NULL;
	for (i = 0; i < results.gl_pathc; i++)
	{
		read_key_config(results.gl_pathv[i], &tmp_err);
		if (tmp_err) {
			k_critical_error(tmp_err);
			g_clear_error(&tmp_err);
		}
	}

	globfree(&results);
}
