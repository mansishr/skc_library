#define G_LOG_DOMAIN "keyagent-key"
#include "key-agent/key_agent.h"
#include "key-agent/types.h"

#include "internal.h"
#include "k_errors.h"


using namespace keyagent;

KEYAGENT_DEFINE_ATTRIBUTES()

extern "C" void
keyagent_key_set_cache_id(keyagent_key *_key, gint cache_id)
{
    DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, _key);
    key->cache_state.id = cache_id;
}

extern "C" gint
keyagent_key_get_cache_id(keyagent_key *_key)
{
    DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, _key);
    return key->cache_state.id;
}

extern "C" gint
keyagent_key_get_session_cache_id(keyagent_key *_key)
{
    DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, _key);
    return keyagent_session_get_cache_id(key->session);
}

extern "C" keyagent_key *
keyagent_key_lookup(const char *url)
{
    return (keyagent_key *)g_hash_table_lookup(keyagent::key_hash, url);
}

extern "C" keyagent_key *
keyagent_key_create(keyagent_url url, keyagent_keytype type, keyagent_attributes_ptr attrs, const char *session_id, gint cache_id, GError **error)
{
    DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, keyagent_key_lookup(url));
    keyagent_session *session = NULL;

    if (key) {
        goto out;
    }

    if (!attrs || !session_id) {
        g_set_error (error, KEYAGENT_ERROR, KEYAGENT_ERROR_KEY_CREATE_PARAMS, "Invalid arguments for %s", __func__);
        return NULL;
    }

    session = keyagent_session_lookup(session_id);
    if (!session) {
        if (error && *error)
            k_critical_error(*error);
        g_set_error (error, KEYAGENT_ERROR, KEYAGENT_ERROR_KEY_CREATE_INVALID_SESSION_ID, "Invalid session-id for %s", session_id);
        return NULL;
    }

    key = (keyagent_key_real *)g_new0(keyagent_key_real, 1);
    key->url = g_string_new(url);
    g_hash_table_insert(keyagent::key_hash, key->url->str, key);
	key->type = type;
	key->attributes = keyagent_attributes_ref(attrs);
	key->session = session;
    keyagent_key_set_cache_id((keyagent_key *)key, cache_id);
out:
    if (cache_id == -1)
        keyagent_cache_key((keyagent_key *)key, error);

    keyagent_stm_set_session((keyagent_session *)session, error);
    return (keyagent_key *)key;
}

extern "C" gboolean
keyagent_key_free(keyagent_key *_key)
{
    DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, _key);

    if (key) return TRUE;

    return TRUE;
}

extern "C" void
keyagent_key_hash_key_free(gpointer data)
{
}

extern "C" void
keyagent_key_hash_value_free(gpointer data)
{
    g_autoptr(GError) tmp_error = NULL;
    keyagent_key_real *key = (keyagent_key_real *)data;
    keyagent_uncache_key((keyagent_key *)key, &tmp_error);
    g_string_free(key->url, TRUE);
	keyagent_attributes_unref(key->attributes);
    g_free(key);
}

extern "C" const char *
keyagent_key_get_stmname(keyagent_key *_key, GError **error)
{
    DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, _key);
    return keyagent_session_get_stmname(key->session, error);
}

typedef struct {
    GList *l;
    keyagent_session_real *session; 
} delete_key_list;

static void
build_delete_key_list(gpointer hashkey, gpointer data, gpointer user_data)
{
    keyagent_key_real *key = (keyagent_key_real*)data;
    delete_key_list *list = (delete_key_list *)user_data;
    if (key->session != (keyagent_session *)list->session)
        return;
    list->l = g_list_append(list->l, key);
}

static void
delete_key(gpointer data, gpointer user_data)
{
    keyagent_key_real *key = (keyagent_key_real*)data;
    g_hash_table_remove(keyagent::key_hash, key->url->str);
}

extern "C" void
keyagent_key_remove_by_session(keyagent_session *session)
{
    delete_key_list list = {NULL,NULL};
    list.session = (keyagent_session_real *)session;
    g_hash_table_foreach(keyagent::key_hash, build_delete_key_list, &list);
    g_list_foreach(list.l, delete_key, NULL);
    g_list_free(list.l);
}
