
#include "key-agent/key_agent.h"
#include "key-agent/types.h"

#include "internal.h"
#include <errno.h>
#include "k_errors.h"
#include <libgda/libgda.h>
#include <libgda/gda-blob-op.h>
#include <sql-parser/gda-sql-parser.h>

typedef struct {
    keyagent_buffer_ptr swk;
    gint cache_id;
    char *label;
} session_data;

static void
session_data_free(session_data *data)
{
    if (data->label)
        g_free(data->label);

    keyagent_buffer_unref(data->swk);
    g_free(data);
}

static session_data *
get_session_from_model(GdaDataModel *model, int row, GError **error) {
    session_data *data = g_new0(session_data, 1);

    const GValue *value = gda_data_model_get_value_at(model, 0, row, error);
    data->cache_id = g_value_get_int(value);

    value = gda_data_model_get_value_at(model, 1, row, error);
    g_assert(G_VALUE_TYPE(value) == G_TYPE_STRING);
    data->label = g_strdup(g_value_get_string(value));

    value = gda_data_model_get_value_at(model, 2, row, error);
    g_assert(G_VALUE_TYPE(value) == GDA_TYPE_BLOB);

    GdaBlob *blob = (GdaBlob *) gda_value_get_blob(value);
    gsize size = gda_blob_op_get_length(blob->op);
    gda_blob_op_read_all(blob->op, (GdaBlob *) blob);
    data->swk = keyagent_buffer_alloc(NULL, size);
    memcpy(keyagent_buffer_data(data->swk), blob->data.data, size);
    return data;
}

extern "C" gboolean
keyagent_cache_loadsessions(GError **error)
{
    GdaSqlParser *parser;
    GdaStatement *stmt;
    GdaDataModel *model;
    const GValue *value;
    GdaBlob *blob;
    parser = gda_sql_parser_new ();
    gboolean ret = FALSE;

    stmt = gda_sql_parser_parse_string(parser, "SELECT session_id, stm_label, swk FROM sessions", NULL, error);

    g_object_unref (parser);
    if (!stmt) return FALSE;
    model = gda_connection_statement_execute_select (GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), stmt, NULL, error);
    g_object_unref (stmt);
    if (!model) return FALSE;

    gint rows = gda_data_model_get_n_rows (model);
    gint i;

    ret = TRUE;
    for (i = 0; i < rows; ++i) {
        session_data *data = get_session_from_model(model, i, error);
        if (!data) {
            ret = FALSE;
            break;
        }

        keyagent_session_real *session = (keyagent_session_real *) keyagent_session_create(data->label, data->swk, data->cache_id, error);
        session_data_free(data);
    }
    g_object_unref (model);
    out:
    return ret;
}

static session_data *
get_session(const char *label, GError **error)
{
    GdaSqlParser *parser;
    GdaStatement *stmt;
    GdaSet *params;
    GdaDataModel *model;
    session_data *session_data;

    parser = gda_sql_parser_new ();
    stmt = gda_sql_parser_parse_string(parser,
            "SELECT session_id, stm_label, swk FROM sessions WHERE stm_label=##label::gchararray",
            NULL, error);

    g_object_unref (parser);
    if (!stmt) goto out;

    if (!gda_statement_get_parameters (stmt, &params, error)) {
        g_object_unref (stmt);
        goto out;
    }
    g_assert (gda_set_set_holder_value (params, NULL, "label", label));
    model = gda_connection_statement_execute_select (GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), stmt, params, error);
    g_object_unref (params);
    g_object_unref (stmt);
    if (!model) goto out;

    session_data = get_session_from_model(model, 0, error);
    g_object_unref (model);
    out:
    return session_data;
}

extern "C" gboolean
keyagent_cache_session(keyagent_session *_session, GError **error)
{
    GdaStatement *stmt;
    GdaSet *params;
    GdaSqlParser *parser;
    session_data *session_data = NULL;
    GValue *v_stmlabel, *v_swk;
    keyagent_session_real *session = (keyagent_session_real *)_session;
    gint cache_id = -1;
    gboolean ret = TRUE;

    g_rw_lock_writer_lock(&keyagent::localcache::cache_rwlock);
    if (!keyagent::localcache::cache_sessions) {
        cache_id = keyagent_cache_generate_fake_id();
        goto out;
    }

    v_stmlabel = gda_value_new_from_string (session->name->str, G_TYPE_STRING);
    v_swk = gda_value_new_blob (keyagent_buffer_data(session->swk), keyagent_buffer_length(session->swk));

    if (!gda_connection_insert_row_into_table (GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), "sessions", error, "stm_label", v_stmlabel, "swk", v_swk, NULL)) {
        k_info_error(*error);
        ret = FALSE;
        goto out;
    }
    gda_connection_commit_transaction(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), NULL, NULL);
    session_data = get_session(session->name->str, error);
    cache_id = session_data->cache_id;
    session_data_free(session_data);
out:
    keyagent_session_set_cache_id(_session, cache_id);
    g_rw_lock_writer_unlock(&keyagent::localcache::cache_rwlock);
    return ret;
}
