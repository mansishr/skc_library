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
    GHashTable *url_hash;
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


extern "C" gboolean 
keyagent_init(const char *filename, GError **err)
{
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
	keyagent::stm_hash = g_hash_table_new (g_str_hash, g_str_equal);
	keyagent::url_hash = g_hash_table_new (g_direct_hash, g_direct_equal);

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
	g_list_foreach(modules, initialize_stm, err); 
	g_list_free_full(modules, free_char_pointer);  

    keyagent::key_directory = g_string_new(key_config_get_string(keyagent::config, "core", "key-directory", err));
	if (*err != NULL) {
		return FALSE;
	}
	return TRUE;
}

static void
_loadkey(gpointer keyid, gpointer data, gpointer user_data)
{
	keyagent_real_npm *npm = (keyagent_real_npm *)data;
	keyagent_url url = (keyagent_url)user_data;
	GError *err = NULL;

	if (!npm->initialized)
		return;

	if (!NPM_MODULE_OP(npm,register)(url))
		return;

	keyagent_key *key = g_new0(keyagent_key, 1);
	key->id = keyagent_keyid_from_url(url);
	key->url = g_string_new(url);

	if (NPM_MODULE_OP(npm,key_load)(key, &err) == FALSE) {
		g_string_free(key->url, TRUE);
		g_free(key);
		return;
	}

	g_hash_table_insert(keyagent::url_hash, GINT_TO_POINTER(key->id), key);
	k_info_msg("%s mapped to npm %s", url, keyagent_get_module_label(npm));
}
          
extern "C" keyagent_keyid
keyagent_loadkey(keyagent_url url, GError **err)
{
	keyagent_keyid keyid = keyagent_keyid_from_url ((const gchar *)url);
	keyagent_key *key = (keyagent_key *)g_hash_table_lookup(keyagent::url_hash, GINT_TO_POINTER(keyid));
	if (key)
	{
		k_info_msg("found key %p for url %s cached!", key, url);
		return keyid;
	}
	g_hash_table_foreach(keyagent::npm_hash, _loadkey, url);
	key = (keyagent_key *)g_hash_table_lookup(keyagent::url_hash, GINT_TO_POINTER(keyid));
	if (!key)
	{
		k_critical_msg("Not able to load key %s!", url);
		return 0;
	}

	return keyagent_stm_load_key(key);
}



