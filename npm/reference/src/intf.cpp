#define G_LOG_DOMAIN "npm-reference"
#include <glib.h>
#include <errno.h>
#include <iostream>
#include <memory>
#include <string>
#include "config-file/key_configfile.h"
#include "k_errors.h"
#include "key-agent/key_agent.h"
#include "key-agent/npm/npm.h"
#include "key-agent/stm/stm.h"

#include <jsoncpp/json/json.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>  
#include <glib.h>
#include <glib/gi18n.h>

using namespace std;

namespace reference_npm {
	GString *configfile;
	GString *server_url;
	gboolean debug;
	GString *certfile  = NULL;
	GString *keyname = NULL;
	keyagent_curl_ssl_opts ssl_opts;
}

typedef struct {
    int tries;
    keyagent_module *stm;
    keyagent_session *session;
	keyagent_url url;
} loadkey_info;

extern "C" void
npm_finalize(GError **err)
{
	//TODO free up resource on error case
}

extern "C" const char * 
npm_init(const char *config_directory, GError **err)
{
    reference_npm::configfile = g_string_new(g_build_filename(config_directory, "reference_npm.ini", NULL));
    void *config = key_config_openfile(reference_npm::configfile->str, err);
	gchar *server = key_config_get_string(config, "core", "server", err);
	if (*err) {
    	//g_message ("Error loading npm - referenece: %s", err->message);
    	k_critical_error(*err);
		return NULL;
	}
	reference_npm::server_url = g_string_new(server);
	reference_npm::debug = key_config_get_boolean_optional(config, "core", "debug", FALSE);

	memset(&reference_npm::ssl_opts, 0, sizeof (keyagent_curl_ssl_opts));
	reference_npm::certfile = g_string_new(NULL);
	reference_npm::keyname = g_string_new(NULL);
	keyagent_get_certificate_files(reference_npm::certfile, reference_npm::keyname, err);
	reference_npm::ssl_opts.certfile = reference_npm::certfile->str;
	reference_npm::ssl_opts.keyname = reference_npm::keyname->str;
    reference_npm::ssl_opts.certtype = "PEM";
    reference_npm::ssl_opts.keytype = "PEM";

	return "REFERENCE";
}

extern "C" gboolean
npm_register(keyagent_url url, GError **err)
{
	return TRUE;
}

std::string get_json_value(Json::Value value, const char *key)
{
    char exceptstr[32]="Error in parsing json key:";
    if( !value.isMember(key))
    {
		//cout<< "Exception occured" <<endl;
        strcat(exceptstr, key);
		throw std::runtime_error(exceptstr);
	}
    //printf("going to return value\n");
    return value[key].asString();
}

void json_print(Json::Value &val)
{
    switch (val.type()) {
        case Json::nullValue: k_debug_msg("null"); break;
        case Json::intValue: k_debug_msg("int %d", val.asLargestInt()); break;
        case Json::uintValue: k_debug_msg("uint %d", val.asLargestUInt()); break;
        case Json::realValue: k_debug_msg("real %f",  val.asDouble()); break;
        case Json::stringValue: k_debug_msg("string %s", val.asString().c_str()); break;
        case Json::booleanValue: k_debug_msg("boolean %d", val.asBool()); break;
        case Json::arrayValue: k_debug_msg("array of length %d", val.size()); break;
        case Json::objectValue: k_debug_msg("object of length %d", val.size()); break;
        default: k_debug_msg("wrong type"); break;
    }
}

static Json::Value parse_data(keyagent_buffer_ptr data)
{
	Json::Value jsonData;
    Json::Reader jsonReader;

    if (jsonReader.parse((char *)keyagent_buffer_data(data), (char *)(keyagent_buffer_data(data) + keyagent_buffer_length(data)), jsonData))
    {
		if (reference_npm::debug) 
		{
        	k_debug_msg("JSON data received:");
        	k_debug_msg("%s", jsonData.toStyledString().c_str());
		}
	}

	return jsonData;
}

static keyagent_buffer_ptr
decode64_json_attr(Json::Value json_data, const char *name)
{
	try {
		const char *val = json_data[name].asCString();
		gsize len = 0;
		guchar *tmp = g_base64_decode(val, &len);
		return keyagent_buffer_alloc(tmp, len);
	} catch (...) {
		k_critical_msg("could not find %s", name);
		return keyagent_buffer_alloc(NULL, 0);
	}
}

static gboolean
start_session(loadkey_info *info, Json::Value &transfer_data, GError **error)
{

	GString *session_url  = g_string_new(transfer_data["link"]["challenge-replyto"]["href"].asCString());
	GString *session_method  = g_string_new(transfer_data["link"]["challenge-replyto"]["method"].asCString());

	GPtrArray *headers;
	headers = g_ptr_array_new ();
	g_ptr_array_add (headers, (gpointer) "Accept: application/octet-stream");
	g_ptr_array_add (headers, (gpointer) "Content-Type: application/json");

	if (!keyagent_stm_get_by_name("SW", &info->stm))
        return FALSE;
	keyagent_buffer_ptr challenge = NULL;
	if (!keyagent_stm_get_challenge(keyagent_get_module_label(info->stm), &challenge, error))
	    return FALSE;

	keyagent_debug_with_checksum("NPM:CHALLENGEl:REAL", keyagent_buffer_data(challenge), keyagent_buffer_length(challenge));

	keyagent_buffer_ptr return_data = keyagent_buffer_alloc(NULL,0);
	Json::Value session_data;
	session_data["challenge-type"] = keyagent_get_module_label(info->stm);
	session_data["challenge"] = transfer_data["challenge"];
	session_data["quote"] = g_base64_encode(keyagent_buffer_data(challenge), keyagent_buffer_length(challenge));

	keyagent_buffer_unref(challenge);

	Json::StreamWriterBuilder builder;
    builder.settings_["indentation"] = "";
    GString *post_data = g_string_new(Json::writeString(builder, session_data).c_str());
	long res_status =  keyagent_curlsend(session_url, headers, post_data, return_data, &reference_npm::ssl_opts, reference_npm::debug);
	g_string_free(post_data, TRUE);

	if (res_status == -1)
		g_error("%s failed", session_url->str);

	k_debug_msg("return status %d", res_status);
    Json::Value session_return_data = parse_data(return_data);
	keyagent_buffer_unref(return_data);

    k_debug_msg("res_status %d\n%s", res_status, session_return_data.toStyledString().c_str());

    if (res_status != 200) return FALSE;

    keyagent_buffer_ptr protected_swk = decode64_json_attr(session_return_data, "swk");

	info->session =  keyagent_session_create(keyagent_get_module_label(info->stm), protected_swk, -1, error);

	return (info->session ? TRUE : FALSE);
}

#define SET_KEY_ATTR(DATA, ATTRS, JSON_KEY, NAME) do { \
    keyagent_buffer_ptr NAME = decode64_json_attr(DATA, JSON_KEY); \
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR((ATTRS), NAME); \
    keyagent_buffer_unref(NAME); \
} while (0)



static gboolean
__npm_loadkey(loadkey_info *info, GError **err)
{
	keyagent_keytype keytype;

	if (info->tries > 1) return FALSE;
	info->tries += 1;

	gboolean ret = FALSE;
	gchar *keyid = g_path_get_basename (info->url);
	GString *stm_names = keyagent_stm_get_names();
	GString *url = g_string_new(reference_npm::server_url->str);
	g_string_append(url,"/keys/transfer");
	k_debug_msg("stm-names: %s", stm_names->str);

	GPtrArray *headers;
	headers = g_ptr_array_new ();
	g_ptr_array_add (headers, (gpointer) "Accept: application/json");
	g_ptr_array_add (headers, (gpointer) "Content-Type: application/json");

    if (!info->session) {
	    GString *accept_challenge_header = g_string_new("Accept-Challenge: "); 
	    g_string_append(accept_challenge_header, stm_names->str);
	    g_ptr_array_add (headers, (gpointer) accept_challenge_header->str);
    }

	GString *keyid_header = g_string_new("KeyId: "); 
	g_string_append(keyid_header, keyid);
	g_ptr_array_add (headers, (gpointer) keyid_header->str);

	keyagent_buffer_ptr return_data = keyagent_buffer_alloc(NULL,0);

	long res_status =  keyagent_curlsend(url, headers, NULL, return_data, &reference_npm::ssl_opts, reference_npm::debug);

	if (res_status == -1)
		g_error("%s failed", url->str);

	Json::Value transfer_data = parse_data(return_data);
	json_print(transfer_data);
	k_debug_msg("res_status %d\n%s", res_status, transfer_data.toStyledString().c_str());

	if (res_status == 401) {
		const std::string status = transfer_data["status"].asString();
		const std::string type = transfer_data["faults"]["type"].asString();
		if (status == "failure" && type == "not-authorized") {
		    if (start_session(info, transfer_data, err))
				ret = __npm_loadkey(info, err);
		}

	} else if ((res_status & 200) == 200) {

		keyagent_attributes_ptr attrs = keyagent_attributes_alloc();

		try {
			keytype = ( get_json_value(transfer_data["data"], "algorithm") == "RSA" ? KEYAGENT_RSAKEY : KEYAGENT_ECCKEY);
			SET_KEY_ATTR(transfer_data["data"], attrs, "payload", KEYDATA);
            SET_KEY_ATTR(transfer_data["data"], attrs, "STM_TEST_DATA", STM_TEST_DATA);
            SET_KEY_ATTR(transfer_data["data"], attrs, "STM_TEST_SIG", STM_TEST_SIG);
        } catch (exception& e){
				k_critical_msg("%s\n", e.what());
                return FALSE;
		}
		ret = (keyagent_key_create(info->url, keytype, attrs, info->session, -1, err) != NULL ? TRUE : FALSE);
	}
	return ret;
}

extern "C" gboolean
npm_key_load(keyagent_url url, GError **error)
{
    loadkey_info info = {0, NULL, NULL};
    info.url = url;
    info.session = keyagent_session_lookup("SW");
	gboolean ret = __npm_loadkey(&info, error);
	return ret;
}
