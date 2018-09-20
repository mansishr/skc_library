
#include "key-agent/key_agent.h"
#include "key-agent/types.h"

#include "internal.h"
#include <errno.h>
#include "k_errors.h"


extern "C" keyagent_session *
keyagent_session_lookup(const char *label)
{
    return (keyagent_session *)g_hash_table_lookup(keyagent::session_hash, label);
}

extern "C" keyagent_session *
keyagent_session_id_lookup(gint id)
{
    return (keyagent_session *)g_hash_table_lookup(keyagent::session_id_hash, GINT_TO_POINTER(id));
}

extern "C" void
keyagent_session_set_cache_id(keyagent_session *_session, gint cache_id)
{
    DECLARE_KEYAGENT_REAL_PTR(session, keyagent_session, _session);
    session->cache_state.id = cache_id;
    if (cache_id != -1) {
        g_hash_table_insert(keyagent::session_id_hash, GINT_TO_POINTER(cache_id), session);
    }
}

extern "C" gint
keyagent_session_get_cache_id(keyagent_session *_session)
{
    DECLARE_KEYAGENT_REAL_PTR(session, keyagent_session, _session);
    return session->cache_state.id;
}

extern "C" keyagent_session *
keyagent_session_create(const char *label, keyagent_buffer_ptr swk, gint cache_id, GError **error)
{
    DECLARE_KEYAGENT_REAL_PTR(session, keyagent_session, keyagent_session_lookup(label));

    if (session) {
        if (!keyagent_buffer_equal(session->swk, swk)) {
            keyagent_buffer_unref(session->swk);
            session->swk = keyagent_buffer_ref(swk);
        }
        goto out;
    }
    session = (keyagent_session_real *)g_new0(keyagent_session_real, 1);
    session->name = g_string_new(label);
    session->swk = keyagent_buffer_ref(swk);
    keyagent_session_set_cache_id((keyagent_session *)session, cache_id);
    g_hash_table_insert(keyagent::session_hash, session->name->str, session);
out:

    if (cache_id == -1)
        keyagent_cache_session((keyagent_session *)session, error);

    keyagent_stm_set_session((keyagent_session *)session, error);
    return (keyagent_session *)session;
}

extern "C" void
keyagent_session_save(keyagent_session *session)
{
    //return (keyagent_session *)g_hash_table_lookup(keyagent::session_hash, label);
}

extern "C" void
keyagent_session_hash_key_free(gpointer data)
{
    k_info_msg("%s", __func__);

}

extern "C" void
keyagent_session_hash_value_free(gpointer data)
{
    k_info_msg("%s", __func__);
}

extern "C" const char *
keyagent_session_get_stmname(keyagent_session *_session, GError **error)
{
    DECLARE_KEYAGENT_REAL_PTR(session, keyagent_session, _session);
    return session->name->str;
}

