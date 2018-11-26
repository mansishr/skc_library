#define G_LOG_DOMAIN "keyagent-init"

#include <string>
#include <iostream>
#include <libgen.h>
#include "internal.h"
#include "config-file/key_configfile.h"
#include "k_errors.h"
#include "key-agent/key_agent.h"
#include "key-agent/stm/stm.h"
#include "key-agent/npm/npm.h"

namespace keyagent {
    GString *configdirectory;
	GString *configfilename;
	void *config;
    GString *npm_directory;
    GString *stm_directory;
    GString *key_directory;
    GString *cert;
    GString *certkey;
    GHashTable *npm_hash;
    GHashTable *stm_hash;
    GHashTable *key_hash;
	GHashTable *session_hash;
	GHashTable *swk_type_hash;
    GRWLock rwlock;
}

/* Return GList of paths described in location string */
static GList *
handle_wildcards (GString *location)
{
    GList *res = NULL;
    gchar *path = g_path_get_dirname (location->str);
    gchar *pattern = g_path_get_basename (location->str);
    GPatternSpec *pspec = g_pattern_spec_new (pattern);
    GDir *dir = g_dir_open (path, 0, NULL);
    const gchar *name;

    k_debug_msg ("matching %s from %s\n", pattern, path);

    if (!dir) {
        k_critical_msg ("opening directory %s failed\n", path);
        goto out;
    }

    while ((name = g_dir_read_name (dir)) != NULL) {
        if (g_pattern_match_string (pspec, name)) {
            res = g_list_append (res, g_strjoin ("/", path, name, NULL));
            k_debug_msg ("  found %s\n", name);
        }
    }

    g_dir_close (dir);
out:
    g_pattern_spec_free (pspec);
    g_free (pattern);
    g_free (path);
    return res;
}

static void
free_char_pointer(gpointer data)
{
	g_free(data);
}

gboolean
do_keyagent_init(const char *filename, GError **err)
{

    g_rw_lock_init (&keyagent::rwlock);

    keyagent::configdirectory = g_string_new(g_path_get_dirname(filename));
	keyagent::configfilename = g_string_new(filename);
	keyagent::config = key_config_openfile(filename, err);
	if (*err != NULL)
	{
        k_critical_msg ("Error loading key file: %s %p", (*err)->message, keyagent::config);
		return FALSE;
	}
    keyagent::npm_directory = g_string_new(key_config_get_string(keyagent::config, "core", "npm-directory", err));
	if (*err != NULL) {
		return FALSE;
	}
    keyagent::stm_directory = g_string_new(key_config_get_string(keyagent::config, "core", "stm-directory", err));
	if (*err != NULL) {
		return FALSE;
	}
    keyagent::cert = g_string_new(key_config_get_string(keyagent::config, "core", "cert", err));
	if (*err != NULL) {
		return FALSE;
	}
    keyagent::certkey = g_string_new(key_config_get_string(keyagent::config, "core", "certkey", err));
	if (*err != NULL) {
		return FALSE;
	}

	keyagent::npm_hash = g_hash_table_new (g_str_hash, g_str_equal);
	keyagent::stm_hash = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, NULL);
	keyagent::key_hash = g_hash_table_new_full (g_str_hash, g_str_equal, keyagent_key_hash_key_free, keyagent_key_hash_value_free);
	keyagent::session_hash = g_hash_table_new_full (g_direct_hash, g_direct_equal, keyagent_session_hash_key_free, keyagent_session_hash_value_free);


	GString *pattern = g_string_new(keyagent::npm_directory->str);
	g_string_append(pattern, "/npm_*.so");
	GList *modules = handle_wildcards(pattern);
	if (!modules) {
		k_critical_msg("Did not find any npms that matched pattern %s", pattern->str);
		return FALSE;
	}
	g_list_foreach(modules, initialize_npm, err); 
	g_list_free_full(modules, free_char_pointer);  

	g_string_assign(pattern, keyagent::stm_directory->str);
	g_string_append(pattern, "/stm_*.so");
	modules = handle_wildcards(pattern);
	if (!modules) {
		k_critical_msg("Did not find any stms that matched pattern %s", pattern->str);
		return FALSE;
	}

    if (!keyagent_session_init(err))
        return FALSE;

	g_list_foreach(modules, initialize_stm, err); 
	g_list_free_full(modules, free_char_pointer);  

    keyagent::key_directory = g_string_new(key_config_get_string(keyagent::config, "core", "key-directory", err));
	if (*err != NULL) {
		return FALSE;
	}

    if (!keyagent_cache_init(err))
        return FALSE;


    return TRUE;
}


extern "C" gboolean
keyagent_init(const char *filename, GError **err)
{
    static gsize init = 0;
    static GError *error = NULL;
    if (g_once_init_enter (&init))
    {
        do_keyagent_init(filename, &error);
        g_once_init_leave (&init, 1);
    }

    if (error != NULL)
    {
        g_propagate_error(err, error);
        return FALSE;
    }
    return TRUE;
}

typedef struct {
    keyagent_url url;
    GError **err;
} loadkey_t;

static gboolean
_loadkey(gpointer keyid, gpointer data, gpointer user_data)
{
	gboolean ret = FALSE;
	keyagent_npm_real *npm = (keyagent_npm_real *)data;
	loadkey_t *loadkey  = (loadkey_t *)user_data;
    g_autoptr(GError) tmp_error = NULL;


	if (!npm->initialized)
		return ret;

	if (!NPM_MODULE_OP(npm,register)(loadkey->url, &tmp_error))
		goto out;

	ret = TRUE;
	if (NPM_MODULE_OP(npm,key_load)(loadkey->url, loadkey->err) == FALSE)
		goto out;
	k_debug_msg("%s mapped to npm %s", loadkey->url, keyagent_get_module_label(npm));

out:
	return ret;
}
          
extern "C" keyagent_key *
keyagent_loadkey(keyagent_url url, GError **err)
{
	keyagent_key *key = NULL;
    loadkey_t loadkey;

    loadkey.url = url;
    loadkey.err = err;

    g_rw_lock_writer_lock(&keyagent::rwlock);

	if ((key = keyagent_key_lookup(url)) != NULL)
	{
		k_debug_msg("found key %p for url %s cached!", key, url);
		goto out;
	}

	if( !g_hash_table_find(keyagent::npm_hash, _loadkey, &loadkey) )
	{
		k_set_error (err, KEYAGENT_ERROR_NPM_URL_UNSUPPORTED, 
				            "Warining: Error in NPM Register\n");
		goto out;
	}

	if ((key = keyagent_key_lookup(url)) == NULL)
	{
		k_critical_msg("Not able to load key %s!", url);
        goto out;
	}

	if (!keyagent_stm_load_key(key, err)) {
        keyagent_key_free(key);
        key = NULL;
    }
    out:
    g_rw_lock_writer_unlock(&keyagent::rwlock);
    return key;
}



