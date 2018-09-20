
#include "key-agent/key_agent.h"
#include "key-agent/types.h"

#include "internal.h"
#include <errno.h>
#include "k_errors.h"
#include <libgda/libgda.h>
#include <libgda/gda-blob-op.h>
#include <sql-parser/gda-sql-parser.h>

typedef struct {
    keyagent_buffer_ptr sealed_data;
    char *url;
    gint cache_id;
    gint key_type;
    gint session_id;
} key_data;

static void
key_data_free(key_data *data)
{
    if (data->url)
        g_free(data->url);

    if (data->sealed_data)
        keyagent_buffer_unref(data->sealed_data);
    g_free(data);
}

typedef struct {
    keyagent_buffer_ptr attr_value;
    GString *attr_name;
    gint cache_id;
    gint stm_id;
} keyattr_data;

static void
keyattr_data_free(keyattr_data *data)
{
    keyagent_buffer_unref(data->attr_value);
    if (data->attr_name)
        g_string_free(data->attr_name, TRUE);
    g_free(data);
}

static key_data *
get_key_from_model(GdaDataModel *model, int row, GError **error) {
    key_data *data = g_new0(key_data, 1);

    const GValue *value = gda_data_model_get_value_at(model, 0, row, error);
    data->cache_id = g_value_get_int(value);

    value = gda_data_model_get_value_at(model, 1, row, error);
    data->session_id = g_value_get_int(value);

    value = gda_data_model_get_value_at(model, 2, row, error);
    data->key_type = g_value_get_int(value);

    value = gda_data_model_get_value_at(model, 3, row, error);
    g_assert(G_VALUE_TYPE(value) == GDA_TYPE_BLOB);
    GdaBlob *blob = (GdaBlob *) gda_value_get_blob(value);
    gsize size = gda_blob_op_get_length(blob->op);
    gda_blob_op_read_all(blob->op, (GdaBlob *) blob);
    data->sealed_data = keyagent_buffer_alloc(NULL, size);
    memcpy(keyagent_buffer_data(data->sealed_data), blob->data.data, size);

    value = gda_data_model_get_value_at(model, 4, row, error);
    data->url = g_strdup(g_value_get_string(value));
    return data;
}

static keyattr_data *
get_keyattr_from_model(GdaDataModel *model, int row, GError **error) {
    keyattr_data *data = g_new0(keyattr_data, 1);

    const GValue *value = gda_data_model_get_value_at(model, 0, row, error);
    data->cache_id = g_value_get_int(value);

    value = gda_data_model_get_value_at(model, 1, row, error);
    g_assert(G_VALUE_TYPE(value) == GDA_TYPE_BLOB);
    GdaBlob *blob = (GdaBlob *) gda_value_get_blob(value);
    gsize size = gda_blob_op_get_length(blob->op);
    gda_blob_op_read_all(blob->op, (GdaBlob *) blob);
    data->attr_value = keyagent_buffer_alloc(NULL, size);
    memcpy(keyagent_buffer_data(data->attr_value), blob->data.data, size);
    return data;
}

extern "C" keyagent_buffer_ptr
keyagent_cache_loadkey_attr(gint key_id, const char *attr_name, GError **error)
{
    GdaSqlParser *parser;
    GdaStatement *stmt;
    GdaDataModel *model;
    const GValue *value;
    GdaBlob *blob;
    GdaSet *params;
    parser = gda_sql_parser_new ();

    stmt = gda_sql_parser_parse_string(parser,
            "SELECT keyattr_id, attr_value FROM key_attributes WHERE key_id=##keyid::gint and attr_name=##attrname::gchararray",
            NULL, error);

    g_object_unref (parser);
    if (!stmt) return FALSE;
    if (!gda_statement_get_parameters (stmt, &params, error)) {
        g_object_unref (stmt);
        return NULL;
    }
    g_assert (gda_set_set_holder_value (params, NULL, "keyid", key_id));
    g_assert (gda_set_set_holder_value (params, NULL, "attrname", attr_name));
    model = gda_connection_statement_execute_select (GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), stmt, params, error);
    g_object_unref (params);
    g_object_unref (stmt);
    if (!model) return NULL;

    value = gda_data_model_get_value_at(model, 1, 0, error);
    g_assert(G_VALUE_TYPE(value) == GDA_TYPE_BLOB);
    blob = (GdaBlob *) gda_value_get_blob(value);
    gsize size = gda_blob_op_get_length(blob->op);
    gda_blob_op_read_all(blob->op, (GdaBlob *) blob);
    keyagent_buffer_ptr attr_value = keyagent_buffer_alloc(NULL, size);
    memcpy(keyagent_buffer_data(attr_value), blob->data.data, size);
    g_object_unref (model);
    return attr_value;
}

#define SET_KEY_ATTR(KEYID, ATTRS, NAME, ERROR) do { \
    keyagent_buffer_ptr NAME = keyagent_cache_loadkey_attr((KEYID), #NAME, (ERROR)); \
    keyagent_debug_with_checksum("CACHE-R-"#NAME, keyagent_buffer_data(NAME), keyagent_buffer_length(NAME)); \
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR((ATTRS), NAME); \
    keyagent_buffer_unref(NAME); \
} while (0)

static gboolean
create_rsa_key(key_data *data, GError **error)
{
    keyagent_attributes_ptr attrs = keyagent_attributes_alloc();
    keyagent_session *session = keyagent_session_id_lookup(data->session_id);
    SET_KEY_ATTR(data->cache_id, attrs, KEYDATA, error);
    SET_KEY_ATTR(data->cache_id, attrs, IV, error);
    SET_KEY_ATTR(data->cache_id, attrs, STM_DATA, error);
    keyagent_key_create(data->url, KEYAGENT_RSAKEY, attrs, session, data->cache_id, error);
    keyagent_attributes_unref(attrs);
}

static gboolean
create_ecc_key(key_data *data, GError **error)
{
    keyagent_attributes_ptr attrs = keyagent_attributes_alloc();
    keyagent_session *session = keyagent_session_id_lookup(data->session_id);
    SET_KEY_ATTR(data->cache_id, attrs, KEYDATA, error);
    SET_KEY_ATTR(data->cache_id, attrs, IV, error);
    SET_KEY_ATTR(data->cache_id, attrs, STM_DATA, error);
    keyagent_key_create(data->url, KEYAGENT_ECCKEY, attrs, session, data->cache_id, error);
    keyagent_attributes_unref(attrs);
}

extern "C" gboolean
keyagent_cache_loadkeys(GError **error)
{
    GdaSqlParser *parser;
    GdaStatement *stmt;
    GdaDataModel *model;
    const GValue *value;
    GdaBlob *blob;
    parser = gda_sql_parser_new ();
    stmt = gda_sql_parser_parse_string(parser, "SELECT key_id, session_id, key_type, sealed_data, url FROM keys", NULL, error);

    g_object_unref (parser);
    if (!stmt) return FALSE;
    model = gda_connection_statement_execute_select (GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), stmt, NULL, error);
    g_object_unref (stmt);
    if (!model) return FALSE;

    gint rows = gda_data_model_get_n_rows (model);
    gint i;
    for (i = 0; i < rows; ++i) {
        key_data *data = get_key_from_model(model, i, error);
        if (!data) continue;
        
        switch (data->key_type) {
        case KEYAGENT_RSAKEY:
            create_rsa_key(data, error);
            break;
        case KEYAGENT_ECCKEY:
            create_ecc_key(data, error);
            break;
        default:
            ;
        }
        key_data_free(data);
    }
    g_object_unref (model);
    return TRUE;
}

static key_data *
get_key(const char *url, GError **error)
{
    GdaSqlParser *parser;
    GdaStatement *stmt;
    GdaSet *params;
    GdaDataModel *model;
    key_data *key_data;

    parser = gda_sql_parser_new ();
    stmt = gda_sql_parser_parse_string(parser,
            "SELECT key_id, session_id, key_type, sealed_data, url FROM keys WHERE url=##url::gchararray",
            NULL, error);

    g_object_unref (parser);
    if (!stmt) goto out;

    if (!gda_statement_get_parameters (stmt, &params, error)) {
        g_object_unref (stmt);
        goto out;
    }
    g_assert (gda_set_set_holder_value (params, NULL, "url", url));
    model = gda_connection_statement_execute_select (GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), stmt, params, error);
    g_object_unref (params);
    g_object_unref (stmt);
    if (!model) goto out;

    key_data = get_key_from_model(model, 0, error);
    g_object_unref (model);
    out:
    return key_data;
}

static gboolean
cache_key_attr(keyagent_key_real *key, const char *attr_name, keyagent_buffer_ptr attr_value, gint cache_id, GError **error)
{
    GdaStatement *stmt;
    GdaSet *params;

    GdaSqlParser *parser;
    GValue *v_attrname, *v_attrvalue;
    GValue v_cacheid = G_VALUE_INIT;

    g_value_init (&v_cacheid, G_TYPE_INT);
    g_value_set_int (&v_cacheid, cache_id);
    v_attrname = gda_value_new_from_string (attr_name, G_TYPE_STRING);
    v_attrvalue = gda_value_new_blob (keyagent_buffer_data(attr_value), keyagent_buffer_length(attr_value));

    if (!gda_connection_insert_row_into_table (GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), 
        "key_attributes", error, 
        "key_id", &v_cacheid, 
        "attr_name", v_attrname,
        "attr_value", v_attrvalue,
        NULL)) {
        k_info_error(*error);
        return FALSE;
    }
    gda_connection_commit_transaction(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), NULL, NULL);
    return TRUE;
}

#define CACHE_KEY_ATTR(VAL, KEY, CACHEID, ERROR) do { \
    keyagent_buffer_ptr tmp; \
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR((KEY)->attributes, VAL, tmp); \
    keyagent_debug_with_checksum("CACHE-W-"#VAL, keyagent_buffer_data(tmp), keyagent_buffer_length(tmp)); \
    cache_key_attr((KEY), #VAL, tmp, CACHEID, ERROR); \
} while (0)

static gboolean
cache_rsa_key_attrs(keyagent_key_real *key, gint cache_id, GError **error)
{
    CACHE_KEY_ATTR(IV, key, cache_id, error);
    CACHE_KEY_ATTR(KEYDATA, key, cache_id, error);
    CACHE_KEY_ATTR(STM_DATA, key, cache_id, error);
    return TRUE;
}

static gboolean
cache_ecc_key_attrs(keyagent_key_real *key, gint cache_id, GError **error)
{
    CACHE_KEY_ATTR(IV, key, cache_id, error);
    CACHE_KEY_ATTR(KEYDATA, key, cache_id, error);
    CACHE_KEY_ATTR(STM_DATA, key, cache_id, error);
    return TRUE;
}

extern "C" gboolean
keyagent_cache_key(keyagent_key *_key, GError **error)
{
    GdaStatement *stmt;
    GdaSet *params;
    GdaSqlParser *parser;
    key_data *key_data = NULL;
    GValue *v_url, *v_sealeddata;
    GValue v_cacheid, v_keytype;
    keyagent_key_real *key = (keyagent_key_real *)_key;
    keyagent_buffer_ptr tmp;
    gint cache_id = -1;
    gboolean ret = TRUE;

    g_rw_lock_writer_lock(&keyagent::localcache::cache_rwlock);

    if (!keyagent::localcache::cache_keys) {
        cache_id = keyagent_cache_generate_fake_id();
        goto out;
    }

    v_url = gda_value_new_from_string (key->url->str, G_TYPE_STRING);
    //v_sealeddata = gda_value_new_blob (keyagent_buffer_data(key->sealed_data), keyagent_buffer_length(key->sealed_data));

    tmp = keyagent_buffer_alloc(NULL, 2);
    v_sealeddata = gda_value_new_blob (keyagent_buffer_data(tmp), keyagent_buffer_length(tmp));
    
    g_value_init (&v_cacheid, G_TYPE_INT);
    g_value_init (&v_keytype, G_TYPE_INT);
    g_value_set_int (&v_cacheid, keyagent_key_get_session_cache_id((keyagent_key *)key));
    g_value_set_int (&v_keytype, key->type);

    if (!gda_connection_insert_row_into_table (GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), 
        "keys", error, 
        "url", v_url,
        "sealed_data", v_sealeddata,
        "session_id", &v_cacheid,
        "key_type", &v_keytype,
        NULL)) {
        k_info_error(*error);
        ret = FALSE;
        goto out;
    }
    gda_connection_commit_transaction(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), NULL, NULL);

    keyagent_buffer_unref(tmp);

    key_data = get_key(key->url->str, error);
    cache_id = key_data->cache_id;
    switch (key_data->key_type) {
    case KEYAGENT_RSAKEY:
        cache_rsa_key_attrs(key, cache_id, error);
        break;
    case KEYAGENT_ECCKEY:
        cache_ecc_key_attrs(key, cache_id, error);
        break;
    default:
        ;
    }
    key_data_free(key_data);
out:
    keyagent_key_set_cache_id((keyagent_key *)key, cache_id);
    g_rw_lock_writer_unlock(&keyagent::localcache::cache_rwlock);

    return ret;
}
