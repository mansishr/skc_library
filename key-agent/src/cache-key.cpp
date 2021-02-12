#include <libgda/libgda.h>
#include <libgda/gda-blob-op.h>
#include <sql-parser/gda-sql-parser.h>
#include "internal.h"
#include "k_debug.h"
extern "C" {
#include "safe_lib.h"
}

static GdaDataModel *global_model = NULL;
static GList *global_delete_list = NULL;

typedef struct {
	k_buffer_ptr sealed_data;
	char *url;
	gint cache_id;
	int key_type;
	gchar *session_id;
}key_data;

extern "C" void DLL_LOCAL
__key_data_free(key_data *data)
{
	if(data->url)
		g_free(data->url);
	if(data->session_id)
		g_free(data->session_id);
	if(data->sealed_data)
		k_buffer_unref(data->sealed_data);
	g_free(data);
}

typedef struct {
	k_buffer_ptr attr_value;
	GString *attr_name;
	gint cache_id;
	gint stm_id;
}keyattr_data;

DLL_LOCAL key_data* 
__get_key_from_model(GdaDataModel *model, int row, GError **error) {
	key_data *data = g_new0(key_data, 1);

	const GValue *value = gda_data_model_get_value_at(model, 0, row, error);
	data->cache_id = g_value_get_int(value);

	value = gda_data_model_get_value_at(model, 1, row, error);
	data->session_id = g_strdup(g_value_get_string(value));

	value = gda_data_model_get_value_at(model, 2, row, error);
	data->key_type = g_value_get_int(value);

	value = gda_data_model_get_value_at(model, 3, row, error);
	g_assert(G_VALUE_TYPE(value) == GDA_TYPE_BLOB);
	GdaBlob *blob = (GdaBlob *) gda_value_get_blob(value);
	gsize size = gda_blob_op_get_length(blob->op);
	gda_blob_op_read_all(blob->op, (GdaBlob *) blob);
	data->sealed_data = k_buffer_alloc(NULL, size);
	memcpy_s(k_buffer_data(data->sealed_data), k_buffer_length(data->sealed_data), blob->data.data, size);

	value = gda_data_model_get_value_at(model, 4, row, error);
	data->url = g_strdup(g_value_get_string(value));
	return data;
}

extern "C" k_buffer_ptr DLL_LOCAL
__keyagent_cache_loadkey_attr(gint key_id, const char *attr_name, GError **error)
{
	GdaSqlParser *parser;
	GdaStatement *stmt;
	GdaDataModel *model;
	const GValue *value;
	GdaBlob *blob;
	GdaSet *params;
	parser = gda_sql_parser_new();

	stmt = gda_sql_parser_parse_string(parser,
		"SELECT keyattr_id, attr_value FROM key_attributes WHERE key_id=##keyid::gint and attr_name=##attrname::gchararray",
		 NULL, error);

	g_object_unref(parser);
	if(!stmt)
		return FALSE;
	if(!gda_statement_get_parameters(stmt, &params, error)) {
		g_object_unref (stmt);
		return NULL;
	}
	g_assert (gda_set_set_holder_value(params, NULL, "keyid", key_id));
	g_assert (gda_set_set_holder_value(params, NULL, "attrname", attr_name));
	model = gda_connection_statement_execute_select(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), stmt, params, error);
	g_object_unref(params);
	g_object_unref(stmt);
	if(!model)
		return NULL;

	gint rows = gda_data_model_get_n_rows(model);
	if(rows == 0)
	{
		return NULL;
	}

	value = gda_data_model_get_value_at(model, 1, 0, error);
	g_assert(G_VALUE_TYPE(value) == GDA_TYPE_BLOB);
	blob = (GdaBlob *) gda_value_get_blob(value);
	gsize size = gda_blob_op_get_length(blob->op);
	gda_blob_op_read_all(blob->op, (GdaBlob *) blob);
	k_buffer_ptr attr_value = k_buffer_alloc(NULL, size);
	memcpy_s(k_buffer_data(attr_value), k_buffer_length(attr_value), blob->data.data, size);
	g_object_unref(model);
	return attr_value;
}

#define SET_KEY_ATTR(KEYID, ATTRS, NAME, ERROR) do { \
	k_buffer_ptr NAME = __keyagent_cache_loadkey_attr((KEYID), #NAME, (ERROR)); \
	if(NAME == NULL)\
		return FALSE;\
	k_debug_generate_checksum("CACHE-R-"#NAME, k_buffer_data(NAME), k_buffer_length(NAME)); \
	KEYAGENT_KEY_ADD_BYTEARRAY_ATTR((ATTRS), NAME); \
	k_buffer_unref(NAME); \
}while(0)

extern "C" gboolean DLL_LOCAL
__create_rsa_key(key_data *data, GError **error)
{
	gboolean ret = TRUE;
	k_attributes_ptr attrs = k_attributes_alloc();
	SET_KEY_ATTR(data->cache_id, attrs, KEYDATA, error);
	k_attributes_unref(attrs);
    return ret;
}

extern "C" void DLL_LOCAL
__delete_key(int key_id, const char *table, const char *field)
{
	GdaSqlParser *parser=NULL;
	GdaStatement *stmt = NULL;
	GdaSet *params = NULL;
	g_autoptr(GError) tmp_error = NULL;
	int ret = -1;
	GString *sql = g_string_new(NULL);
	if(!sql)
		goto out;

	g_string_printf(sql,"DELETE FROM %s WHERE %s=##keyid::gint", table, field);

	parser = gda_sql_parser_new();
	if(!parser)
		goto out;

	stmt = gda_sql_parser_parse_string(parser, sql->str, NULL, &tmp_error);
	g_object_unref(parser);

	if(!stmt)
		goto out;

	if(!gda_statement_get_parameters(stmt, &params, &tmp_error))
		goto out;

	g_assert(gda_set_set_holder_value (params, NULL, "keyid", key_id));
	ret = gda_connection_statement_execute_non_select(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), stmt, params, NULL, &tmp_error);

	if(ret >= 0)
		gda_connection_commit_transaction(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), NULL, NULL);
out:
	if(ret == -1 && tmp_error!=NULL)
		k_info_error(tmp_error);
	if(params)
		g_object_unref(params);
	if(stmt)
		g_object_unref(stmt);
	if(parser)
		g_object_unref(parser);
	if(sql)
		g_string_free(sql, TRUE);
    return;
}

extern "C" void DLL_LOCAL
__delete_key_and_attrs(int id)
{
	__delete_key(id, "key_attributes", "key_id");
	__delete_key(id, "keys", "id");
	__delete_key(id, "key_policy_attributes", "key_id");
	return;
}

extern "C" void DLL_LOCAL
__delete_key_from_list(gpointer data, gpointer user_data)
{
	gint cache_id = GPOINTER_TO_INT(data);
	__delete_key_and_attrs(cache_id);
}

extern "C" gboolean DLL_LOCAL
__keyagent_cache_loadkeys(GError **error)
{
	GdaSqlParser *parser;
	GdaStatement *stmt;
	gboolean ret = FALSE;
	gint cache_id;
	parser = gda_sql_parser_new ();
	stmt = gda_sql_parser_parse_string(parser, "SELECT id, session_id, key_type, sealed_data, url FROM keys", NULL, error);

	g_object_unref(parser);
	if(!stmt)
		return FALSE;
	global_model = gda_connection_statement_execute_select(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), stmt, NULL, error);
	g_object_unref(stmt);
	if(!global_model)
		return FALSE;

	gint rows = gda_data_model_get_n_rows(global_model);
	gint i;
	for (i = 0; i < rows; ++i) {
		g_autoptr(GError) tmp_error = NULL;
		key_data *data = __get_key_from_model(global_model, i, error);
		if(!data)
			continue;
        
		cache_id = data->cache_id;
		switch (data->key_type) {
			case KEYAGENT_RSAKEY:
				ret = __create_rsa_key(data, &tmp_error);
				break;
			default:
				;
			}
		__key_data_free(data);
		if(!ret)
			global_delete_list = g_list_append(global_delete_list, GINT_TO_POINTER(cache_id));
	}
	g_object_unref (global_model);
	global_model = NULL;
	g_list_foreach(global_delete_list, __delete_key_from_list, NULL);
	g_list_free(global_delete_list);
	global_delete_list = NULL;
	return TRUE;
}

DLL_LOCAL key_data*
__get_key(const char *url, GError **error)
{
	GdaSqlParser *parser = NULL;
	GdaStatement *stmt = NULL;
	GdaSet *params = NULL;
	GdaDataModel *model = NULL;
	key_data *key_data = NULL;

	parser = gda_sql_parser_new();
	stmt = gda_sql_parser_parse_string(parser, "SELECT id, session_id, key_type, sealed_data, url FROM keys WHERE url=##url::gchararray", NULL, error);

	g_object_unref(parser);
	if(!stmt)
		goto out;

	if(!gda_statement_get_parameters(stmt, &params, error)) {
		goto out;
	}
	g_assert (gda_set_set_holder_value(params, NULL, "url", url));
	model = gda_connection_statement_execute_select(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), stmt, params, error);

	if(!model)
		goto out;

	key_data = __get_key_from_model(model, 0, error);
	g_object_unref(model);
out:
	if(params)
		g_object_unref(params);
	if(stmt)
		g_object_unref(stmt);
	return key_data;
}

extern "C" gboolean DLL_LOCAL
__cache_key_attr(keyagent_key_real *key, const char *attr_name, k_buffer_ptr attr_value, gint key_id, GError **error)
{
	GValue *v_attrname, *v_attrvalue;
	GValue v_keyid = G_VALUE_INIT;

	g_value_init(&v_keyid, G_TYPE_INT);
	g_value_set_int(&v_keyid, key_id);
	v_attrname = gda_value_new_from_string(attr_name, G_TYPE_STRING);
	v_attrvalue = gda_value_new_blob(k_buffer_data(attr_value), k_buffer_length(attr_value));

	if(!gda_connection_insert_row_into_table(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer),
	"key_attributes", error, "key_id", &v_keyid, "attr_name", v_attrname, "attr_value", v_attrvalue, NULL)) {
	        k_info_error(*error);
	        return FALSE;
	}
	gda_connection_commit_transaction(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), NULL, NULL);
	return TRUE;
}

#define CACHE_KEY_ATTR(VAL, KEY, KEYID, ERROR, RET) do { \
	k_buffer_ptr tmp; \
	KEYAGENT_KEY_GET_BYTEARRAY_ATTR((KEY)->attributes, VAL, tmp); \
	k_debug_generate_checksum("CACHE-W-"#VAL, k_buffer_data(tmp), k_buffer_length(tmp)); \
	RET = __cache_key_attr((KEY), #VAL, tmp, KEYID, ERROR); \
}while(0)

extern "C" gboolean DLL_LOCAL
__cache_rsa_key_attrs(keyagent_key_real *key, gint key_id, GError **error)
{
	gboolean ret = FALSE;
	CACHE_KEY_ATTR(KEYDATA, key, key_id, error, ret);
	return ret;
}

extern "C" gboolean DLL_LOCAL
__keyagent_cache_key(keyagent_key *_key, GError **error)
{
	key_data *key_data = NULL;
	GValue *v_url, *v_sealeddata, *v_session_id;
	GValue v_keytype;
	keyagent_key_real *key = (keyagent_key_real *)_key;
	k_buffer_ptr tmp = NULL;;
	gint cache_id = -1;
	gboolean ret = TRUE;

	g_rw_lock_writer_lock(&keyagent::localcache::cache_rwlock);

	if(!keyagent::localcache::cache_keys) {
		cache_id = __keyagent_cache_generate_fake_id();
		goto out;
	}

	v_url = gda_value_new_from_string(key->url->str, G_TYPE_STRING);
	v_session_id = gda_value_new_from_string(key->session->session_id->str, G_TYPE_STRING);

	tmp = k_buffer_alloc(NULL, 2);
	v_sealeddata = gda_value_new_blob(k_buffer_data(tmp), k_buffer_length(tmp));
    
	g_value_init(&v_keytype, G_TYPE_INT);
	g_value_set_int(&v_keytype, key->type);

	if(!gda_connection_insert_row_into_table(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer),
        "keys", error, "url", v_url, "sealed_data", v_sealeddata, "session_id", v_session_id, "key_type", &v_keytype, NULL)) {
		k_info_error(*error);
		ret = FALSE;
		goto out;
	}
	gda_connection_commit_transaction(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), NULL, NULL);

	key_data = __get_key(key->url->str, error);
	if(key_data) {
		cache_id = key_data->cache_id;
		switch(key_data->key_type) {
			case KEYAGENT_RSAKEY:
				ret = __cache_rsa_key_attrs(key, cache_id, error);
				break;
			default:
				;
		}
		if(!ret) {
			k_critical_error(*error);
			__delete_key_and_attrs(cache_id);
		}
		__key_data_free(key_data);
	}
	else
		ret = FALSE;
out:
	if(tmp)
		k_buffer_unref(tmp);
	__keyagent_key_set_cache_id((keyagent_key *)key, cache_id);
	g_rw_lock_writer_unlock(&keyagent::localcache::cache_rwlock);

	return ret;
}

extern "C" gboolean DLL_LOCAL
__keyagent_uncache_key(keyagent_key *_key, GError **error)
{
	keyagent_key_real *key = (keyagent_key_real *)_key;
	if(global_model) {
		global_delete_list = g_list_append(global_delete_list, GINT_TO_POINTER(key->cache_state.id));
		return TRUE;
	}
	__delete_key_and_attrs(key->cache_state.id);
	return TRUE;
}
