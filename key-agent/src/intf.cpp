#define G_LOG_DOMAIN "keyagent-init"

#include <unistd.h>
#include "internal.h"
#include "config-file/key_configfile.h"

using namespace std;

namespace keyagent {
	GString *configdirectory;
	GString *configfilename;
	void *config;
	GString *npm_directory;
	GString *stm_directory;
	keyagent_keyserver_key_format keyformat;
	gboolean ssl_verify;
	GString *cert;
	GString *certkey;
	GString *cacert;
	GHashTable *npm_hash;
	GHashTable *stm_hash;
	GHashTable *key_hash;
	GHashTable *session_hash;
	GHashTable *swk_type_hash;
	GHashTable *apimodule_loadkey_hash;
	GRWLock rwlock;
	keyagent_npm_callbacks npm_ops;
	keyagent_apimodule_ops apimodule_ops;
	gboolean apimodule_enabled;
}

/* Return GList of paths described in location string */
DLL_LOCAL GList *
__handle_wildcards (GString *location)
{
	GList *res = NULL;
	gchar *path = g_path_get_dirname(location->str);
	gchar *pattern = g_path_get_basename(location->str);
	GPatternSpec *pspec = g_pattern_spec_new(pattern);
	GDir *dir = g_dir_open(path, 0, NULL);
	const gchar *name;

	k_debug_msg("matching %s from %s\n", pattern, path);

	if(!dir) {
		k_critical_msg("opening directory %s failed\n", path);
		goto out;
	}

	while((name = g_dir_read_name(dir)) != NULL) {
		if(g_pattern_match_string(pspec, name)) {
			res = g_list_append(res, g_strjoin ("/", path, name, NULL));
			k_debug_msg("found %s\n", name);
		}
	}
	g_dir_close(dir);
out:
	g_pattern_spec_free(pspec);
	g_free(pattern);
	g_free(path);
	return res;
}

DLL_LOCAL void
__free_char_pointer(gpointer data)
{
	g_free(data);
}

DLL_LOCAL gboolean
__do_keyagent_init(const char *filename, GError **err)
{
	if(filename == NULL)
	{
		g_set_error(err, KEYAGENT_ERROR, KEYAGENT_ERROR_INVALID_CONF_VALUE,
			"Invalid Config file:");
		return FALSE;
	}
	g_rw_lock_init (&keyagent::rwlock);

	keyagent::configdirectory = g_string_new(g_path_get_dirname(filename));
	keyagent::configfilename = g_string_new(filename);
	keyagent::config = key_config_openfile(filename, err);
	if(*err != NULL)
	{
		k_critical_msg("Error loading key file: %s %p", (*err)->message, keyagent::config);
		return FALSE;
	}

	keyagent::npm_directory = g_string_new(key_config_get_string(keyagent::config, "core", "npm-directory", err));
	if(*err != NULL)
		return FALSE;
	keyagent::stm_directory = g_string_new(key_config_get_string(keyagent::config, "core", "stm-directory", err));
	if(*err != NULL)
		return FALSE;
	keyagent::cert = g_string_new(key_config_get_string(keyagent::config, "keyserver_credentials", "certificate", err));
	if(*err != NULL)
		return FALSE;
	keyagent::certkey = g_string_new(key_config_get_string(keyagent::config, "keyserver_credentials", "certificate_key", err));
	if(*err != NULL)
		return FALSE;
	keyagent::cacert = g_string_new(key_config_get_string(keyagent::config, "keyserver_credentials", "ca_certificate", err));
	if(*err != NULL)
		return FALSE;
	gchar *keyformat = key_config_get_string(keyagent::config, "keyserver_credentials", "keyformat", err);
	if(*err != NULL)
		return FALSE;
	
	if(g_strcmp0(keyformat, KEYAGENT_KEY_FORMAT_PKCS11_STR) == 0)
		keyagent::keyformat = KEYAGENT_KEY_FORMAT_PKCS11;
	else if(g_strcmp0( keyformat, KEYAGENT_KEY_FORMAT_PEM_STR) == 0)
		keyagent::keyformat = KEYAGENT_KEY_FORMAT_PEM;
	else {
		g_set_error(err, KEYAGENT_ERROR, KEYAGENT_ERROR_INVALID_KEYFORMAT,
                     "Invalid Key Format:%s, expected key format:{%s/%s}", keyformat, KEYAGENT_KEY_FORMAT_PKCS11_STR, KEYAGENT_KEY_FORMAT_PEM_STR);
		return FALSE;
	}

	if((access( keyagent::cert->str, F_OK ) == -1) || (access( keyagent::cacert->str, F_OK) == -1)) {
		g_set_error(err, KEYAGENT_ERROR, KEYAGENT_ERROR_INVALID_CONF_VALUE,
                     "Invalid Cert Path:%s or  CA Cert Path:%s", keyagent::cert->str, keyagent::cacert->str);
		return FALSE;
	}
	if(keyagent::keyformat == KEYAGENT_KEY_FORMAT_PEM && access( keyagent::certkey->str, F_OK ) == -1)
	{
	        g_set_error(err, KEYAGENT_ERROR, KEYAGENT_ERROR_INVALID_CONF_VALUE,
                     "Invalid Cert Key Path:%s", keyagent::certkey->str);
		return FALSE;
	}

	keyagent::ssl_verify = key_config_get_boolean(keyagent::config, "keyserver_credentials", "ssl_verify", err);
	if(*err != NULL) {
		return FALSE;
	}

	LOOKUP_KEYAGENT_INTERNAL_NPM_OPS(&keyagent::npm_ops);
	keyagent::npm_hash = g_hash_table_new(g_str_hash, g_str_equal);
	if(keyagent::npm_hash == NULL)
	{
		g_set_error(err, KEYAGENT_ERROR, KEYAGENT_ERROR_OUT_OF_MEMORY,"Error in Hash Table creation\n");
		return FALSE;
	}

	keyagent::stm_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
	keyagent::key_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, __keyagent_key_hash_key_free, __keyagent_key_hash_value_free);
	keyagent::session_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, __keyagent_session_hash_key_free, __keyagent_session_hash_value_free);
	keyagent::apimodule_loadkey_hash = g_hash_table_new_full(g_str_hash, g_str_equal, keyagent_request_id_destory, NULL);

	GString *pattern = g_string_new(keyagent::npm_directory->str);
	g_string_append(pattern, "/npm_*.so");
	GList *modules = __handle_wildcards(pattern);
	if(!modules) {
		g_set_error(err, KEYAGENT_ERROR, KEYAGENT_ERROR_INVALID_CONF_VALUE,
                    "Invalid NPM module path:%s", pattern->str);
		return FALSE;
	}
	g_list_foreach(modules, __initialize_npm, err); 
	g_list_free_full(modules, __free_char_pointer);  

	g_string_assign(pattern, keyagent::stm_directory->str);
	g_string_append(pattern, "/stm_*.so");
	modules = __handle_wildcards(pattern);
	if(!modules) {
		g_set_error(err, KEYAGENT_ERROR, KEYAGENT_ERROR_INVALID_CONF_VALUE,
                    "Invalid STM module path:%s", pattern->str);
		return FALSE;
	}

	if(!__keyagent_session_init(err))
	        return FALSE;

	g_list_foreach(modules, __initialize_stm, err); 
	g_list_free_full(modules, __free_char_pointer);  

	if(!__keyagent_cache_init(err))
		return FALSE;
    return TRUE;
}

extern "C" gboolean DLL_PUBLIC
keyagent_init(const char *filename, GError **err)
{
	static gsize init = 0;
	static GError *error = NULL;
	if(g_once_init_enter(&init))
	{
		__do_keyagent_init(filename, &error);
		g_once_init_leave(&init, 1);
	}

	if(error != NULL)
	{
		g_propagate_error(err, error);
		k_critical_error(error);
		return FALSE;
	}
	return TRUE;
}

typedef struct {
	keyagent_url url;
	void *module_data;
	GError **err;
}loadkey_t;

DLL_LOCAL gboolean
_loadkey(gpointer keyid, gpointer data, gpointer user_data)
{
	gboolean ret = FALSE;
	keyagent_npm_real *npm = (keyagent_npm_real *)data;
	loadkey_t *loadkey  = (loadkey_t *)user_data;
	g_autoptr(GError) tmp_error = NULL;
	keyagent_keyload_details details;
	const char *request_id = NULL;
	keyagent_request request;

	if(!npm->initialized)
		return ret;

	if(!NPM_MODULE_OP(npm,register)(loadkey->url, &tmp_error))
		goto out;

	request_id = keyagent_generate_request_id();
	request.module_data = loadkey->module_data;
	request.stm_name = NULL;
	request.npm_name = npm->npm.label;

	g_hash_table_insert(keyagent::apimodule_loadkey_hash, (gpointer)request_id, (gpointer)&request);

	memset(&details, 0, sizeof(details));
	details.request_id = strdup(request_id);
	details.url = loadkey->url;
	if(keyagent::apimodule_enabled)
		details.stm_names = __keyagent_stm_get_apimodule_enabled_names();
	else
		details.stm_names = __keyagent_stm_get_names();
	details.ssl_opts.ca_certfile = strdup(keyagent::cacert->str);
	details.ssl_opts.certfile = strdup(keyagent::cert->str);
	details.ssl_opts.keyname = strdup(keyagent::certkey->str);
	details.ssl_opts.certtype = FORMAT_PEM;
	details.ssl_opts.ssl_verify = keyagent::ssl_verify;
	details.ssl_opts.keytype = (keyagent::keyformat == KEYAGENT_KEY_FORMAT_PEM )?FORMAT_PEM:FORMAT_ENG;
	LOOKUP_KEYAGENT_INTERNAL_NPM_OPS(&details.cbs);

	// Now, we always return TRUE even if npm fails to load the key.
	// TRUE tells key-agent to stop looking for an NPM that matches they key
	ret = TRUE;

	NPM_MODULE_OP(npm,key_load)(&details, loadkey->err);
	if(!tmp_error) {
		keyagent_key_real *key = NULL;
		if((key = (keyagent_key_real *)__keyagent_key_lookup(loadkey->url)) != NULL) {
			ret = __keyagent_stm_load_key(request_id, (keyagent_key *)key, &tmp_error);
		}
	}

	g_hash_table_remove(keyagent::apimodule_loadkey_hash, request_id);

	if(tmp_error != NULL)
		g_propagate_error(loadkey->err, tmp_error);

	if(details.stm_names)
		g_string_free(details.stm_names, TRUE);
	free((void *)details.request_id);
	free((void *)details.ssl_opts.certfile);
	free((void *)details.ssl_opts.keyname);
out:
	return ret;
}
          
extern "C"
gboolean DLL_PUBLIC
keyagent_apimodule_register(const char *label, keyagent_apimodule_ops *ops, GError **err)
{
	gboolean ret = TRUE;
	g_return_val_if_fail((err || (err?*err:NULL)) && ops, FALSE);
	memcpy(&keyagent::apimodule_ops,ops, sizeof(keyagent_apimodule_ops));
	if(label)
		ret = __keyagent_stm_apimodule_enable(label);
	return ret;
}

extern "C" gboolean DLL_PUBLIC
keyagent_loadkey_with_moduledata(keyagent_url url, void *module_data, GError **err)
{
	g_return_val_if_fail(url, FALSE);
	gchar **url_tokens = NULL;
	keyagent_key *key = NULL;
	gboolean ret = FALSE;

	url_tokens = g_strsplit(url, ":", -1);
	if((g_strcmp0(url_tokens[0], "") == 0) || (g_strcmp0(url_tokens[1], "") == 0))
	{
		k_critical_msg("Expected token missing in url:%s \n", url);
		goto cleanup;
	}
	loadkey_t loadkey;
	loadkey.url = url;
	loadkey.err = err;
	loadkey.module_data = module_data;

	g_rw_lock_writer_lock(&keyagent::rwlock);

	if((key = __keyagent_key_lookup(url)) != NULL)
	{
		k_debug_msg("found key %p for url %s cached!", key, url);
		ret = TRUE;
		goto out;
	}

	if(!g_hash_table_find(keyagent::npm_hash, _loadkey, &loadkey))
	{
		k_set_error(err, KEYAGENT_ERROR_NPM_URL_UNSUPPORTED, 
				            "Warning: Error in NPM Register. URL is not supported\n");
		goto out;
	}

	if((key = __keyagent_key_lookup(url)) == NULL)
	{
		k_critical_msg("Not able to load key %s!", url);
	        goto out;
	}
	ret = TRUE;

out:
	g_rw_lock_writer_unlock(&keyagent::rwlock);
	return ret;
cleanup:
	g_strfreev(url_tokens);
	return ret;
}
