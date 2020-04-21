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

extern "C" gboolean DLL_LOCAL
__keyagent_key_policy_add(keyagent_url url, k_attributes_ptr policy_attrs, gint cache_id, GError **error)
{
	gboolean ret = FALSE;
	DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, __keyagent_key_lookup(url));
	if(!key || !policy_attrs)
	{
		goto out;
	}
	key = (keyagent_key_real *)key;
	key->policy_attributes = k_attributes_ref(policy_attrs);
	ret=TRUE;
out:
	if((cache_id == -1)&&key)
		__keyagent_cache_key_policy((keyagent_key *)key, error);

	return ret;
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

extern "C" gboolean DLL_LOCAL
__keyagent_key_validate_usage_policy(GTimeVal *policy, const gchar* policy_type)
{
	GTimeVal ctime;
	gint status = -1;
	gboolean ret = FALSE;
	GDateTime *policy_time = NULL;
	GDateTime *current_time = NULL;

	policy_time = g_date_time_new_from_timeval_local(policy);
	if(policy_time == NULL)
	{
		k_critical_msg("Error in converting date time struct\n");
		return ret;
	}
	g_get_current_time (&ctime);
	current_time = g_date_time_new_from_timeval_local(&ctime);
	status = g_date_time_compare(policy_time, current_time);
	if((strcmp(policy_type, "NOT_AFTER") ==0  && (status == 1)) || ((strcmp(policy_type, "NOT_BEFORE") == 0
		|| strcmp(policy_type, "CREATED_AT") == 0 ) && (status == -1)))
		ret = TRUE;
	g_date_time_unref(policy_time);
	g_date_time_unref(current_time);
	return ret;
}

#define VALIDATE_KEY_POLICY_ATTR(KEY, VAL) do { \
	gboolean RET = FALSE; \
    k_policy_buffer_ptr tmp; \
    KEYAGENT_KEY_GET_POLICY_ATTR((KEY)->policy_attributes, VAL, tmp); \
    RET = __keyagent_key_validate_usage_policy(k_policy_buffer_data(tmp), #VAL); \
	if(RET == FALSE) \
		return RET; \
}while(0)

extern "C" gboolean  DLL_LOCAL
__validate_key_usage_policy(keyagent_key_real *key)
{
	VALIDATE_KEY_POLICY_ATTR(key, NOT_BEFORE);
	VALIDATE_KEY_POLICY_ATTR(key, NOT_AFTER);
	VALIDATE_KEY_POLICY_ATTR(key, NOT_AFTER);
	
	return TRUE;
}

extern "C" gboolean 
keyagent_key_checkpolicy(keyagent_url url, int op, gint size, GError **err)  
{
	gboolean ret = FALSE;
	DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, __keyagent_key_lookup(url));
	if(key == NULL)
	{
		k_critical_msg("Invalid key url:%s\n", url);
		return ret;
	}
	ret = __validate_key_usage_policy(key);
	if(ret != TRUE)
	{   
		k_critical_msg("Invalid key usage policy_date\n");
		__keyagent_key_hash_value_free(key);
	}
	return ret;
}
