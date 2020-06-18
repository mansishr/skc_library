#define G_LOG_DOMAIN "npm-reference"
#include <json/json.h>
#include "config-file/key_configfile.h"
#include "key-agent/key_agent.h"
#include "k_debug.h"
#include "utils/utils.h"

using namespace std;

namespace reference_npm {
	GString *configfile;
	GString *server_url;
	gboolean debug;
}

typedef struct {
	int tries;
	keyagent_keyload_details *details;
	int keyid;
} loadkey_info;

#define k_string_free(string, flag) { if(string) g_string_free((string), flag); }

extern "C" void
npm_finalize(GError **err)
{
}

extern "C" const char * 
npm_init(const char *config_directory, GError **err)
{
	reference_npm::configfile = g_string_new(g_build_filename(config_directory, "reference_npm.ini", NULL));
	void *config = key_config_openfile(reference_npm::configfile->str, err);
	gchar *server = key_config_get_string(config, "core", "server", err);
	if(*err) {
		k_critical_error(*err);
		return NULL;
	}
	reference_npm::server_url = g_string_new(server);
	reference_npm::debug = key_config_get_boolean_optional(config, "core", "debug", FALSE);
	return "REFERENCE";
}

extern "C" gboolean
npm_register(keyagent_url url, GError **err)
{
	g_return_val_if_fail(url, FALSE );
	gchar **url_tokens = NULL;
	gboolean ret = FALSE;

	url_tokens = g_strsplit(url, ":", -1);
	if(!url_tokens[0] || !url_tokens[1] || (g_strcmp0(url_tokens[0], "REFERENCE") != 0)) {
	        if( err ) {
			k_set_error(err, NPM_ERROR_REGISTER, "NPM_URL_UNSUPPORTED:Expected token:%s token missing in url:%s\n",
				"REFERENCE", url);
		}
		goto cleanup;
	}
	ret = TRUE;
cleanup:
	g_strfreev(url_tokens);
	return ret;
}

std::string get_json_value(Json::Value value, const char *key)
{
	if(!value.isMember(key))
	{
		throw std::runtime_error("Error in parsing json key:"+(std::string)key);
	}
	return value[key].asString();
}

void json_print(Json::Value &val)
{
	switch(val.type()) {
        case Json::nullValue: k_debug_msg("null"); break;
        case Json::intValue: k_debug_msg("int %d", val.asLargestInt()); break;
        case Json::uintValue: k_debug_msg("uint %d", val.asLargestUInt()); break;
        case Json::realValue: k_debug_msg("real %f",  val.asDouble()); break;
        case Json::stringValue: k_debug_msg("string %s", val.asString().c_str()); break;
        case Json::booleanValue: k_debug_msg("boolean %d", val.asBool()); break;
        case Json::arrayValue: k_debug_msg("array of length %d", val.size()); break;
        case Json::objectValue: k_debug_msg("object of length %d", val.size()); break;
    }
}

static Json::Value parse_data(k_buffer_ptr data)
{
	Json::Value jsonData;
	Json::CharReaderBuilder builder;
	Json::CharReader * jsonReader = builder.newCharReader();
	std::string err;

	if(jsonReader->parse((char *)k_buffer_data(data), (char *)(k_buffer_data(data) + k_buffer_length(data)), &jsonData, &err))
	{
		if(reference_npm::debug)
		{
			k_debug_msg("JSON data received:");
			k_debug_msg("%s", jsonData.toStyledString().c_str());
		}
	}
	else if(!err.empty())
	{
		k_critical_msg("Failed to parse Json Data: %s\n", err);
	}
	return jsonData;
}

static k_buffer_ptr
decode64_json_attr(Json::Value json_data, const char *name)
{
	try {
		const char *val = json_data[name].asCString();
		gsize len = 0;
		guchar *tmp = g_base64_decode(val, &len);
		return k_buffer_alloc(tmp, len);
	} catch(...) {
		k_critical_msg("could not find %s", name);
		return k_buffer_alloc(NULL, 0);
	}
}

static inline GQuark
KEYAGENT_QUARK_FROM_STR(const char *type, const char *name)
{
	GString *tmp = g_string_new(NULL);
	g_string_printf(tmp, "%s_%s", type, name);
	GQuark q = g_quark_from_string(tmp->str);
	g_string_free(tmp, TRUE);
	return q;
}

void get_session_id_from_header(gpointer data, gpointer user_data)
{
	gchar *str = (gchar *)data;
	gchar ***tokens_ptr = (gchar ***)user_data;
	gchar **tokens = NULL;
	if(g_str_has_prefix (str,"Session-ID:") == TRUE) {
	        tokens = g_strsplit_set (str,":",-1);
		*tokens_ptr = tokens;
	        return;
	}
}

static gboolean
start_session(loadkey_info *info, Json::Value &transfer_data, GError **error)
{
	gboolean ret = FALSE;
	const char *swk_type = NULL;

	GString *post_data = NULL;
	GString *session_url  = NULL;
	GString *session_method  = NULL;
	GString *challenge_type  = NULL;
	GString *session_id = NULL;

	k_buffer_ptr challenge = NULL;
	k_buffer_ptr return_data = NULL;
	k_buffer_ptr protected_swk = NULL;
	GPtrArray *headers = NULL;

	Json::Value session_data;
	Json::Value session_return_data;
	Json::StreamWriterBuilder builder;
	long res_status = -1;

	try {
		session_url = g_string_new(transfer_data["link"]["challenge-replyto"]["href"].asCString());
		session_method = g_string_new(transfer_data["link"]["challenge-replyto"]["method"].asCString());
		challenge_type = g_string_new(transfer_data["challenge_type"].asCString());
		session_id = g_string_new(get_json_value(transfer_data, (const char *)"challenge").c_str());
	} catch(exception &e){
		k_set_error(error, NPM_ERROR_JSON_PARSE,
			"NPM JSON Parse error: %s\n", e.what());
		goto cleanup;
	}

	headers = g_ptr_array_new();
	g_ptr_array_add (headers, (gpointer) "Accept: application/octet-stream");
	g_ptr_array_add (headers, (gpointer) "Content-Type: application/json");

	if(!KEYAGENT_NPM_OP(&info->details->cbs,stm_get_challenge)(info->details->request_id, challenge_type->str, &challenge, error))
	{
	    goto cleanup;
	}

	k_debug_generate_checksum("NPM:CHALLENGEl:REAL", k_buffer_data(challenge), k_buffer_length(challenge));

	return_data = k_buffer_alloc(NULL,0);
	session_data["challenge-type"] = challenge_type->str;
	session_data["challenge"] = session_id->str;
	session_data["quote"] = g_base64_encode(k_buffer_data(challenge), k_buffer_length(challenge));

	builder.settings_["indentation"] = "";
	post_data = g_string_new(Json::writeString(builder, session_data).c_str());
	res_status = skc_https_send(session_url, headers, post_data, NULL, return_data, 
				&info->details->ssl_opts, NULL, reference_npm::debug);

	if(res_status == -1 || res_status == 0)
	{
		k_set_error(error, NPM_ERROR_KEYSERVER_ERROR,
			"Error in connecting key server, url:%s, Invalid http status:%d\n", session_url->str, res_status);
		goto cleanup;
	}

	session_return_data = parse_data(return_data);

	k_debug_msg("res_status %d\n%s", res_status, session_return_data.toStyledString().c_str());

	if(res_status != 200) {
		k_set_error(error, NPM_ERROR_KEYSERVER_ERROR, "Invalid response from keyserver for create-session, code=%d", res_status);
		goto cleanup;
	}

	try {
		protected_swk = decode64_json_attr(session_return_data, "swk");
		swk_type = session_return_data["type"].asCString();
	} catch(exception &e) {
		k_set_error(error, NPM_ERROR_JSON_PARSE,
						"NPM JSON Parse error: %s\n", e.what());
		goto cleanup;
	}

	ret = KEYAGENT_NPM_OP(&info->details->cbs,session_create)(info->details->request_id, challenge_type->str,
        session_id->str, protected_swk, swk_type, error);
cleanup:
	k_string_free(session_url, TRUE);
	k_string_free(session_method, TRUE);
	k_string_free(challenge_type, TRUE);
	k_string_free(session_id, TRUE);
	k_string_free(post_data, TRUE);
	if(headers)
		g_ptr_array_free(headers, TRUE);
	k_buffer_unref(challenge);
	k_buffer_unref(return_data);
	return ret;
}

#define SET_KEY_ATTR(DATA, ATTRS, JSON_KEY, NAME) do { \
	k_buffer_ptr NAME = decode64_json_attr(DATA, JSON_KEY); \
	KEYAGENT_KEY_ADD_BYTEARRAY_ATTR((ATTRS), NAME); \
	k_buffer_unref(NAME); \
}while(0)

static gboolean
__npm_loadkey(loadkey_info *info, GError **err)
{
	if(info->tries > 1) {
		k_set_error(err, NPM_ERROR_LOAD_KEY,
			"%s: %s", __func__, "NPM Load Key tried more than once\n");
		return FALSE;
	}
	info->tries += 1;

	keyagent_keytype keytype;

	gboolean ret = FALSE;
	long res_status =-1;

	GString *session_ids_header = NULL;
	GString *session_ids = NULL;
	GString *url = NULL;
	GString *accept_challenge_header = NULL;
	GString *keyid_header = NULL;

	GPtrArray *res_headers = NULL;
	GPtrArray *headers = NULL;

	Json::Value transfer_data;

	gchar *session_id = NULL;
	gchar **session_id_tokens = NULL;

	k_attributes_ptr attrs = NULL;
	k_buffer_ptr return_data = NULL;
	
	std::string status;
	std::string type;	

	session_ids = KEYAGENT_NPM_OP(&info->details->cbs,session_get_ids)();
	url = g_string_new(reference_npm::server_url->str);
	g_string_append(url,"/keys/transfer");
	k_debug_msg("stm-names: %s", info->details->stm_names->str);

	headers = g_ptr_array_new();
	g_ptr_array_add (headers, (gpointer) "Accept: application/json");
	g_ptr_array_add (headers, (gpointer) "Content-Type: application/json");

	accept_challenge_header = g_string_new("Accept-Challenge: ");
	g_string_append(accept_challenge_header, info->details->stm_names->str);
	g_ptr_array_add (headers, (gpointer) accept_challenge_header->str);

	if(session_ids != NULL && session_ids->len > 0) {
		session_ids_header = g_string_new("Session-ID: ");
		g_string_append(session_ids_header, session_ids->str);
		g_ptr_array_add(headers, (gpointer) session_ids_header->str);
	}

	keyid_header = g_string_new("KeyId: ");
	g_string_append_printf(keyid_header, "%d", info->keyid);
	g_ptr_array_add(headers, (gpointer) keyid_header->str);

	return_data = k_buffer_alloc(NULL,0);
	res_headers = g_ptr_array_new ();

	res_status = skc_https_send(url, headers, NULL, res_headers, return_data,
        &info->details->ssl_opts, NULL, reference_npm::debug);

	if(res_status == -1  || res_status == 0)
	{
		k_set_error(err, NPM_ERROR_KEYSERVER_ERROR,
			"Error in connecting key server, url:%s, Invalid http status:%d\n", url->str, res_status);
		goto cleanup;
	}

	transfer_data = parse_data(return_data);
	json_print(transfer_data);
	k_debug_msg("res_status %d\n%s", res_status, transfer_data.toStyledString().c_str());

	if(res_status == 401) {
		try {
			status = transfer_data["status"].asString();
			type = transfer_data["faults"][0]["type"].asString();
		} catch(exception& e) {
			k_set_error(err, NPM_ERROR_JSON_PARSE,
					"NPM JSON Parse error: %s\n", e.what());
			goto cleanup;
		}
		if(status == "failure" && type == "not-authorized") {
		    if(start_session(info, transfer_data, err)) {
				ret = __npm_loadkey(info, err);
			}
		}

	} else if((res_status & 200) == 200) {

	attrs = k_attributes_alloc();
        g_ptr_array_foreach(res_headers, get_session_id_from_header,  &session_id_tokens);

	try {
		std::string keytype_str = get_json_value(transfer_data["data"], "algorithm");
		if(!keytype_str.compare("RSA"))
			keytype = KEYAGENT_RSAKEY;
		else if(!keytype_str.compare("ECC"))
			keytype = KEYAGENT_ECKEY;
		else
			keytype = KEYAGENT_AESKEY;

		SET_KEY_ATTR(transfer_data["data"], attrs, "payload", KEYDATA);
		SET_KEY_ATTR(transfer_data["data"], attrs, "STM_TEST_DATA", STM_TEST_DATA);
		SET_KEY_ATTR(transfer_data["data"], attrs, "STM_TEST_SIG", STM_TEST_SIG);
	} catch (exception& e) {
		k_set_error(err, NPM_ERROR_JSON_PARSE,
			"NPM JSON Parse error: %s\n", e.what());
		goto cleanup;
	}

	if(!session_id_tokens) {
		k_set_error(err, NPM_ERROR_INVALID_SESSION_DATA,
				"NPM Invalid session data\n");
		goto cleanup;
	}
	session_id = g_strstrip(session_id_tokens[1]);
	if(!session_id) {
		k_set_error(err, NPM_ERROR_INVALID_SESSION_DATA,
			"Invalid session id sent by server: %s - %s\n", session_id_tokens[0],session_id_tokens[1]);
		goto cleanup;
	}
	ret = (KEYAGENT_NPM_OP(&info->details->cbs,key_create)(info->details->request_id,
	info->details->url, keytype, attrs, session_id, err) ? TRUE : FALSE);
    }
cleanup:
	if(session_id_tokens)
		g_strfreev(session_id_tokens);
	k_string_free(session_ids_header, TRUE);
	k_string_free(session_ids, TRUE);
	k_string_free(url, TRUE);
	k_string_free(accept_challenge_header, TRUE);
	k_string_free(keyid_header, TRUE);
	k_buffer_unref(return_data);

	return ret;
}
    
extern "C" gboolean
npm_key_load(keyagent_keyload_details *details, GError **error)
{
	gboolean ret = FALSE;
	loadkey_info info = {0, NULL, 0};
	g_return_val_if_fail((details && details->url), FALSE );
	gchar **url_tokens = NULL;
	url_tokens = g_strsplit (details->url, ":", -1);

	if(!g_strcmp0((const char*)url_tokens[0], "REFERENCE") == 0)
	{
		k_critical_msg("Invalid key url token, url:%s\n", url_tokens[0]);
		goto cleanup;
	}
	info.keyid = atoi(url_tokens[1]);
	info.details = details;
	g_strfreev(url_tokens);
	return __npm_loadkey(&info, error);
cleanup:
	g_strfreev(url_tokens);
	return ret;
}
