#include <libgda/libgda.h>
#include <libgda/gda-blob-op.h>
#include <sql-parser/gda-sql-parser.h>
#include "internal.h"

typedef struct {
	k_buffer_ptr swk;
	gint id;
	char *label;
	char *session_id;
	char *swk_type;
}session_data;

void DLL_LOCAL
__session_data_free(session_data *data)
{
	if(data->label)
		g_free(data->label);

	if(data->session_id)
		g_free(data->session_id);

	if(data->swk_type)
		g_free(data->swk_type);

	k_buffer_unref(data->swk);
	g_free(data);
}

DLL_LOCAL session_data * 
__get_session_from_model(GdaDataModel *model, int row, GError **error) {
	session_data *data = g_new0(session_data, 1);

	GdaBlob *blob = NULL;
	gsize size = 0;

	const GValue *value = gda_data_model_get_value_at(model, 0, row, error);
	data->id = g_value_get_int(value);

	value = gda_data_model_get_value_at(model, 1, row, error);
	g_assert(G_VALUE_TYPE(value) == G_TYPE_STRING);
	data->label = g_strdup(g_value_get_string(value));

	value = gda_data_model_get_value_at(model, 3, row, error);
	g_assert(G_VALUE_TYPE(value) == G_TYPE_STRING);
	data->session_id = g_strdup(g_value_get_string(value));

	value = gda_data_model_get_value_at(model, 4, row, error);
	g_assert(G_VALUE_TYPE(value) == G_TYPE_STRING);
	data->swk_type = g_strdup(g_value_get_string(value));

	value = gda_data_model_get_value_at(model, 2, row, error);
	if(!value || (G_VALUE_TYPE(value) != GDA_TYPE_BLOB))
		goto err;

	blob = (GdaBlob *) gda_value_get_blob(value);
	size = gda_blob_op_get_length(blob->op);
	gda_blob_op_read_all(blob->op, (GdaBlob *) blob);
	data->swk = k_buffer_alloc(NULL, size);
	memcpy(k_buffer_data(data->swk), blob->data.data, size);
	goto out;
err:
	g_free(data);
	data = NULL;
out:
	return data;
}

extern "C" gboolean DLL_LOCAL
__keyagent_cache_loadsessions(GError **error)
{
	GdaSqlParser *parser;
	GdaStatement *stmt;
	GdaDataModel *model;
	const GValue *value;
	GdaBlob *blob;
	parser = gda_sql_parser_new();
	gboolean ret = FALSE;

	stmt = gda_sql_parser_parse_string(parser, "SELECT id, stm_label, swk, session_id, swk_type FROM sessions", NULL, error);

	g_object_unref (parser);
	if(!stmt)
		return FALSE;
	model = gda_connection_statement_execute_select(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), stmt, NULL, error);
	g_object_unref (stmt);
	if(!model)
		return FALSE;

	gint rows = gda_data_model_get_n_rows(model);
	gint i;

	ret = TRUE;

	for(i = 0; i < rows; ++i) {
		session_data *data = __get_session_from_model(model, i, error);
		if(!data) {
			ret = FALSE;
			break;
		}
		__session_data_free(data);
	}
	g_object_unref (model);
out:
	return ret;
}

DLL_LOCAL session_data * 
__get_session(const char *label, GError **error)
{
	GdaSqlParser *parser;
	GdaStatement *stmt;
	GdaSet *params;
	GdaDataModel *model;
	session_data *session_data=NULL;

	parser = gda_sql_parser_new ();
	stmt = gda_sql_parser_parse_string(parser, "SELECT id, stm_label, swk, session_id, swk_type FROM sessions WHERE stm_label=##label::gchararray", NULL, error);

	g_object_unref(parser);
	if(!stmt)
		goto out;

	if(!gda_statement_get_parameters(stmt, &params, error)) {
		g_object_unref (stmt);
		goto out;
	}
	g_assert (gda_set_set_holder_value(params, NULL, "label", label));
	model = gda_connection_statement_execute_select (GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), stmt, params, error);
	g_object_unref (params);
	g_object_unref (stmt);
	if(!model)
		goto out;

	session_data = __get_session_from_model(model, 0, error);
	g_object_unref (model);
out:
	return session_data;
}

extern "C" gboolean DLL_LOCAL
__keyagent_cache_session(keyagent_session *_session, GError **error)
{
	GdaStatement *stmt;
	GdaSet *params;
	GdaSqlParser *parser;
	session_data *session_data = NULL;
	GValue *v_stmlabel, *v_swk, *v_session_id, *v_swk_type;
	keyagent_session_real *session = (keyagent_session_real *)_session;
	gint id = -1;
	gboolean ret = TRUE;

	g_rw_lock_writer_lock(&keyagent::localcache::cache_rwlock);
	if(!keyagent::localcache::cache_sessions) {
		id = __keyagent_cache_generate_fake_id();
		goto out;
	}

	v_stmlabel = gda_value_new_from_string(session->name->str, G_TYPE_STRING);
	v_session_id = gda_value_new_from_string(session->session_id->str, G_TYPE_STRING);
	v_swk_type = gda_value_new_from_string(session->swk_type->str, G_TYPE_STRING);
	v_swk = gda_value_new_blob(k_buffer_data(session->swk), k_buffer_length(session->swk));

	if(!gda_connection_insert_row_into_table(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), "sessions", error, "stm_label", v_stmlabel, "swk", v_swk, "session_id", v_session_id,  "swk_type", v_swk_type, NULL)) {
		k_info_error(*error);
		ret = FALSE;
		goto out;
	}
	gda_connection_commit_transaction(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), NULL, NULL);
	session_data = __get_session(session->name->str, error);

	if(!session_data) {
		g_set_error(error, KEYAGENT_ERROR, KEYAGENT_ERROR_KEY_CREATE_PARAMS, "Invalid arguments for %s", __func__);
		ret=FALSE;
		goto out;
	}
	id = session_data->id;
	__session_data_free(session_data);
    
out:
	 __keyagent_session_set_cache_id(_session, id);
	g_rw_lock_writer_unlock(&keyagent::localcache::cache_rwlock);
return ret;
}
