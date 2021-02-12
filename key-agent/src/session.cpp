#include "internal.h"

static const char *supported_swk_types[] = {
	"AES128-GCM", "AES192-GCM", "AES256-GCM", 
	"AES128-WRAP", "AES192-WRAP", "AES256-WRAP",
	NULL};
	
void DLL_LOCAL
__get_session_ids(gpointer key, gpointer data, gpointer user_data)
{
	keyagent_session_real *session_data = (keyagent_session_real*)data;
	GString *session_ids = (GString *)user_data;

	if(session_ids->len)
		g_string_append_c(session_ids,',');

	if(session_data != NULL)
	{
		g_string_append(session_ids, session_data->name->str);
		g_string_append(session_ids, ":");
		g_string_append(session_ids, session_data->session_id->str);
	}
}

DLL_LOCAL GString *
__keyagent_session_get_ids()
{
	GString *session_ids = g_string_new(NULL);
	g_hash_table_foreach(keyagent::session_hash, __get_session_ids, session_ids);
	if(session_ids->len == 0)
	{
		g_string_free(session_ids, TRUE);
		return NULL;
	}
	return session_ids;
}

DLL_LOCAL keyagent_session * 
__keyagent_session_lookup(const gchar *session_id)
{
	GQuark session_id_quark = g_quark_from_string(session_id);
	return (keyagent_session *)g_hash_table_lookup(keyagent::session_hash, GINT_TO_POINTER(session_id_quark));
}

extern "C" void DLL_LOCAL
__keyagent_session_set_cache_id(keyagent_session *_session, gint cache_id)
{
	DECLARE_KEYAGENT_REAL_PTR(session, keyagent_session, _session);
	session->cache_state.id = cache_id;
}

extern "C" gint DLL_LOCAL
__keyagent_session_get_cache_id(keyagent_session *_session)
{
	DECLARE_KEYAGENT_REAL_PTR(session, keyagent_session, _session);
	return session->cache_state.id;
}

extern "C" gboolean DLL_LOCAL
keyagent_session_create(const char *request_id, const char *label, const char *session_id, k_buffer_ptr swk, const char *swk_type, gint cache_id, GError **error)
{
	DECLARE_KEYAGENT_REAL_PTR(session, keyagent_session, __keyagent_session_lookup(session_id));
	GQuark session_id_quark = g_quark_from_string(session_id);
	gboolean status = FALSE;
	
	GQuark swk_quark = __keyagent_session_lookup_swktype(swk_type);
	if(!swk_quark)
	{
		k_set_error(error, KEYAGENT_ERROR_SESSION_CREATE_INVALID_SWK_TYPE,
			"Unknown swk type %s", swk_type);
		return FALSE;
	}
	GQuark stm_quark = g_quark_from_string(label);
	keyagent_stm_real *stm = (keyagent_stm_real *)g_hash_table_lookup(keyagent::stm_hash, GINT_TO_POINTER(stm_quark));

	if(!stm) {
		k_set_error(error, KEYAGENT_ERROR_SESSION_CREATE_INVALID_LABEL,
			"Unknown stm label %s", label);
		return FALSE;
	}

	if(stm->session) {
		GQuark current_session_id_quark = g_quark_from_string(stm->session->session_id->str);
		if(current_session_id_quark != session_id_quark) {
			g_hash_table_remove(keyagent::session_hash, GINT_TO_POINTER(current_session_id_quark));
		}
	}
	if(session) {
		if(!k_buffer_equal(session->swk, swk)) {
			k_buffer_unref(session->swk);
			session->swk = k_buffer_ref(swk);
			status = TRUE;
		}
		goto out;
	}
	session = (keyagent_session_real *)g_new0(keyagent_session_real, 1);
	session->name = g_string_new(label);
	session->swk = k_buffer_ref(swk);
	session->swk_type	= g_string_new(swk_type);
	session->session_id	= g_string_new(session_id);
	__keyagent_session_set_cache_id((keyagent_session *)session, cache_id);

	g_hash_table_insert(keyagent::session_hash, GINT_TO_POINTER(session_id_quark), session);
	status = TRUE;

out:
	if(cache_id == -1)
		__keyagent_cache_session((keyagent_session *)session, error);

	status = __keyagent_stm_set_session(request_id, (keyagent_session *)session, error);
	return status;
}

extern "C" gboolean DLL_LOCAL
__keyagent_session_create(const char *request_id, const char *label, const char *session_id, k_buffer_ptr swk, const char *swk_type, GError **error)
{
	return keyagent_session_create(request_id, label, session_id, swk, swk_type, -1, error);
}

extern "C" void DLL_LOCAL
__keyagent_session_hash_key_free(gpointer data)
{
}

extern "C" void DLL_LOCAL
__keyagent_session_hash_value_free(gpointer data)
{
	keyagent_session_real *session = (keyagent_session_real *)data;
	__keyagent_key_remove_by_session((keyagent_session *)session);
}

DLL_LOCAL const char * 
__keyagent_session_get_stmname(keyagent_session *_session, GError **error)
{
	DECLARE_KEYAGENT_REAL_PTR(session, keyagent_session, _session);
	return session->name->str;
}

extern "C" GQuark DLL_LOCAL
__keyagent_session_make_swktype(const char *type) 
{
	char **split = g_strsplit(type, "-", -1);
	gchar *res = g_strjoinv("_", split);
	g_strfreev(split);

	GQuark q = keyagent_quark_to_string("SWKTYPE", res);
	g_free (res);
	return q;
}

extern "C" GQuark DLL_LOCAL
__keyagent_session_lookup_swktype(const char *type) 
{
	GQuark q = __keyagent_session_make_swktype(type);
	if(!g_hash_table_lookup(keyagent::swk_type_hash, GUINT_TO_POINTER(q)))
		q = 0;
	return q;
}

extern "C" gboolean DLL_LOCAL
__keyagent_session_init(GError **error)
{
	int i;
	keyagent::swk_type_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
	for (i = 0; supported_swk_types[i]; ++i) {
		GQuark q = __keyagent_session_make_swktype(supported_swk_types[i]);
		g_hash_table_insert(keyagent::swk_type_hash, GUINT_TO_POINTER(q), (gpointer)supported_swk_types[i]);
	}
	return TRUE;
}
