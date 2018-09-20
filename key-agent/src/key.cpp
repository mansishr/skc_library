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
keyagent_key_create(keyagent_url url, keyagent_keytype type, keyagent_attributes_ptr attrs, keyagent_session *session, gint cache_id, GError **error)
{
    DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, keyagent_key_lookup(url));

    if (key) {
        goto out;
    }

    if (!attrs || !session) {
        g_set_error (error, KEYAGENT_ERROR, KEYAGENT_ERROR_KEY_CREATE_PARAMS, "Invalid arguments for %s", __func__);
        return NULL;
    }

    key = (keyagent_key_real *)g_new0(keyagent_key_real, 1);
    key->url = g_string_new(url);
    g_hash_table_insert(keyagent::key_hash, key->url->str, key);
	key->type = type;
	key->attributes = keyagent_attributes_ref(attrs);
	key->session = session;
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

#ifdef NEVER
    key = (keyagent_key_real *)g_new0(keyagent_key_real, 1);
    key->url = g_string_new(url);
    g_hash_table_insert(keyagent::key_hash, key->url->str, key);
	key->type = type;
	key->attributes = attrs;
	key->session = session;
out:
    if (cache_id == -1)
        keyagent_cache_key((keyagent_key *)key, error);

    keyagent_stm_set_session((keyagent_session *)session, error);
    return (keyagent_key *)key;
#endif
    return TRUE;
}

extern "C" void
keyagent_key_hash_key_free(gpointer data)
{
    k_info_msg("%s", __func__);

}

extern "C" void
keyagent_key_hash_value_free(gpointer data)
{
    k_info_msg("%s", __func__);
}

extern "C" const char *
keyagent_key_get_stmname(keyagent_key *_key, GError **error)
{
    DECLARE_KEYAGENT_REAL_PTR(key, keyagent_key, _key);
    return keyagent_session_get_stmname(key->session, error);
}
