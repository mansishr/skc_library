
#include "key-agent/key_agent.h"
#include "key-agent/types.h"

#include "internal.h"
#include <errno.h>
#include "k_errors.h"

static void
get_session_ids(gpointer key, gpointer data, gpointer user_data)
{
    keyagent_session_real *session_data = (keyagent_session_real*)data;
    GString *session_ids = (GString *)user_data;
	char *session = NULL;

    if (session_ids->len)
        g_string_append_c(session_ids,',');

	if ( session_data != NULL)
	{
		g_string_append(session_ids, session_data->name->str);
		g_string_append(session_ids, ":");
		g_string_append(session_ids, session_data->session_id->str);
	}
}

extern "C" GString *
keyagent_session_get_ids()
{
    GString *session_ids = g_string_new(NULL);
    g_hash_table_foreach(keyagent::session_hash, get_session_ids, session_ids);
    if (session_ids->len == 0 )
	{
		g_string_free(session_ids, TRUE);
		return NULL;
	}
    return session_ids;
}

extern "C" keyagent_session *
keyagent_session_lookup(const char *label)
{
    return (keyagent_session *)g_hash_table_lookup(keyagent::session_hash, label);
}

extern "C" keyagent_session *
keyagent_session_str_lookup(const char *session_str)
{
    return (keyagent_session *)g_hash_table_lookup(keyagent::session_hash, session_str);
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

extern "C" gboolean
keyagent_session_create(const char *label, const char *session_id, keyagent_buffer_ptr swk, gint cache_id, GError **error)
{
    DECLARE_KEYAGENT_REAL_PTR(session, keyagent_session, keyagent_session_lookup(label));
	gboolean status = FALSE;

    if (session) {
        if (!keyagent_buffer_equal(session->swk, swk)) {
			keyagent_buffer_unref(session->swk);
            session->swk = keyagent_buffer_ref(swk);
			status = TRUE;
        }
        goto out;
    }
    session = (keyagent_session_real *)g_new0(keyagent_session_real, 1);
    session->name = g_string_new(label);
    session->swk = keyagent_buffer_ref(swk);
	session->session_id	= g_string_new(session_id);
    keyagent_session_set_cache_id((keyagent_session *)session, cache_id);
    g_hash_table_insert(keyagent::session_hash, session->name->str, session);
	status = TRUE;
out:
    if (cache_id == -1)
        keyagent_cache_session((keyagent_session *)session, error);

    keyagent_stm_set_session((keyagent_session *)session, error);
    return status;
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

