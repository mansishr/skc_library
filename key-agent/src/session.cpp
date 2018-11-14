
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
keyagent_session_lookup(const gchar *session_id)
{
    GQuark session_id_quark = g_quark_from_string(session_id);
    return (keyagent_session *)g_hash_table_lookup(keyagent::session_hash, GINT_TO_POINTER(session_id_quark));
}

extern "C" void
keyagent_session_set_cache_id(keyagent_session *_session, gint cache_id)
{
    DECLARE_KEYAGENT_REAL_PTR(session, keyagent_session, _session);
    session->cache_state.id = cache_id;
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
    DECLARE_KEYAGENT_REAL_PTR(session, keyagent_session, keyagent_session_lookup(session_id));
    GQuark session_id_quark = g_quark_from_string(session_id);
	gboolean status = FALSE;
    GQuark stm_quark = g_quark_from_string(label);
    keyagent_stm_real *stm = (keyagent_stm_real *)g_hash_table_lookup(keyagent::stm_hash, GINT_TO_POINTER(stm_quark));

    if (!stm) {
        k_set_error (error, KEYAGENT_ERROR_SESSION_CREATE_INVALID_LABEL, 
            "Unknown stm label %s", label);
        return FALSE;
    }

    if (stm->session) {
        GQuark current_session_id_quark = g_quark_from_string(stm->session->session_id->str);
        if (current_session_id_quark != session_id_quark) {
            g_hash_table_remove(keyagent::session_hash, GINT_TO_POINTER(current_session_id_quark));
        }
    }

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

    g_hash_table_insert(keyagent::session_hash, GINT_TO_POINTER(session_id_quark), session);
	status = TRUE;
out:
    if (cache_id == -1)
        keyagent_cache_session((keyagent_session *)session, error);

    keyagent_stm_set_session((keyagent_session *)session, error);
    return status;
}

extern "C" void
keyagent_session_hash_key_free(gpointer data)
{
}

extern "C" void
keyagent_session_hash_value_free(gpointer data)
{
    keyagent_session_real *session = (keyagent_session_real *)data;
    keyagent_key_remove_by_session((keyagent_session *)session);
}

extern "C" const char *
keyagent_session_get_stmname(keyagent_session *_session, GError **error)
{
    DECLARE_KEYAGENT_REAL_PTR(session, keyagent_session, _session);
    return session->name->str;
}

