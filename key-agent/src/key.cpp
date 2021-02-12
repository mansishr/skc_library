#define G_LOG_DOMAIN "keyagent-key"
#include "internal.h"

using namespace keyagent;

KEYAGENT_DEFINE_ATTRIBUTES()

extern "C" void DLL_LOCAL
__keyagent_key_set_cache_id(keyagent_key *_key, gint cache_id)
{
	DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, _key);
	key->cache_state.id = cache_id;
}

extern "C" gint DLL_LOCAL
__keyagent_key_get_cache_id(keyagent_key *_key)
{
	DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, _key);
	return key->cache_state.id;
}

extern "C" gint DLL_LOCAL
__keyagent_key_get_session_cache_id(keyagent_key *_key)
{
	DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, _key);
	return __keyagent_session_get_cache_id(key->session);
}

DLL_LOCAL keyagent_key * 
__keyagent_key_lookup(const char *url)
{
	GQuark key_url_quark = g_quark_from_string(url);
	if(keyagent::key_hash == NULL)
	{
		k_critical_msg("hash table lookup not found for url:%s \n", url);
		return NULL;
	}
	return (keyagent_key *)g_hash_table_lookup(keyagent::key_hash, GINT_TO_POINTER(key_url_quark));
}

extern "C" GQuark DLL_LOCAL
__keyagent_key_create_with_cacheid(const char *request_id, keyagent_url url, keyagent_keytype type, k_attributes_ptr attrs, const char *session_id, gint cache_id, GError **error)
{
	DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, __keyagent_key_lookup(url));
	GQuark key_quark = g_quark_from_string(url);
	keyagent_session *session = NULL;
	k_buffer_ptr keydata = NULL;

	if(key)
		goto out;

	if(!attrs || !session_id) {
		g_set_error(error, KEYAGENT_ERROR, KEYAGENT_ERROR_KEY_CREATE_PARAMS, "Invalid arguments for %s", __func__);
		return 0;
	}

	KEYAGENT_KEY_GET_BYTEARRAY_ATTR(attrs, KEYDATA, keydata);
	if(!keydata) {
	        g_set_error(error, KEYAGENT_ERROR, KEYAGENT_ERROR_KEY_CREATE_PARAMS, "Invalid arguments for %s", __func__);
		return 0;
	}

	session = __keyagent_session_lookup(session_id);
	if(!session) {
		if(error && *error)
			k_critical_error(*error);
		g_set_error(error, KEYAGENT_ERROR, KEYAGENT_ERROR_KEY_CREATE_INVALID_SESSION_ID, "Invalid session-id for %s", session_id);
		return 0;
	}

	key = (keyagent_key_real *)g_new0(keyagent_key_real, 1);
	key->url = g_string_new(url);
	g_hash_table_insert(keyagent::key_hash, GINT_TO_POINTER(key_quark), key);
	key->type = type;
	key->attributes = k_attributes_ref(attrs);
	key->session = session;
	 __keyagent_key_set_cache_id((keyagent_key *)key, cache_id);
out:
	if(cache_id == -1)
		__keyagent_cache_key((keyagent_key *)key, error);

	return key_quark;
}

extern "C" GQuark DLL_LOCAL
__keyagent_key_create(const char *request_id, keyagent_url url, keyagent_keytype type, k_attributes_ptr attrs, const char *session_id, GError **error)
{
	return __keyagent_key_create_with_cacheid(request_id, url, type, attrs, session_id, -1, error);
}

extern "C" gboolean DLL_LOCAL
__keyagent_key_free(keyagent_key *_key)
{
    DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, _key);
	if(key)
		return TRUE;
	return TRUE;
}

extern "C" void DLL_LOCAL
__keyagent_key_hash_key_free(gpointer data)
{
}

extern "C" void DLL_LOCAL
__keyagent_key_hash_value_free(gpointer data)
{
	g_autoptr(GError) tmp_error = NULL;
	keyagent_key_real *key = (keyagent_key_real *)data;
	__keyagent_uncache_key((keyagent_key *)key, &tmp_error);
	g_string_free(key->url, TRUE);
	k_attributes_unref(key->attributes);
	if(key->policy_attributes)
	{
		k_attributes_unref(key->policy_attributes);
	}
	g_free(key);
}

DLL_LOCAL const char * 
__keyagent_key_get_stmname(keyagent_key *_key, GError **error)
{
	DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, _key);
	return __keyagent_session_get_stmname(key->session, error);
}

typedef struct {
	GList *l;
	keyagent_session_real *session;
}delete_key_list;

static void
__build_delete_key_list(gpointer hashkey, gpointer data, gpointer user_data)
{
	 keyagent_key_real *key = (keyagent_key_real*)data;
	delete_key_list *list = (delete_key_list *)user_data;
	if(key->session != (keyagent_session *)list->session)
		return;
	list->l = g_list_append(list->l, key);
}

static void
__delete_key(gpointer data, gpointer user_data)
{
	keyagent_key_real *key = (keyagent_key_real*)data;
	g_hash_table_remove(keyagent::key_hash, key->url->str);
}

extern "C" void DLL_LOCAL
__keyagent_key_remove_by_session(keyagent_session *session)
{
	delete_key_list list = {NULL,NULL};
	list.session = (keyagent_session_real *)session;
	g_hash_table_foreach(keyagent::key_hash, __build_delete_key_list, &list);
	g_list_foreach(list.l, __delete_key, NULL);
	g_list_free(list.l);
}
