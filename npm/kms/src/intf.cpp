#define G_LOG_DOMAIN "npm-kms"
#include <glib.h>
#include <glib/gi18n.h>
#include <errno.h>
#include <iostream>
#include <memory>
#include <string>
#include "npm/kms/kms.h"
#include <jsoncpp/json/json.h>
#include <exception>


using namespace std;

namespace kms_npm
{
	GString *configfile;
	GString *server_url;
	gboolean debug;
	GString *certfile					= NULL;
	GString *keyname					= NULL;
	keyagent_curl_ssl_opts ssl_opts;
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
		if (kms_npm::debug) 
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
		std::string	json_val			= get_json_value(json_data, name);
		//const char *val					= json_data[name].asCString();
		const char *val					= json_val.c_str();
		gsize len						= 0;
		guchar *tmp						= g_base64_decode(val, &len);
		return keyagent_buffer_alloc(tmp, len);
	} catch (exception  e) {
		k_critical_msg("%s\n", e.what());
		return keyagent_buffer_alloc(NULL, 0);
	}
}

keyagent_buffer_ptr decode_base64_data(keyagent_buffer_ptr ptr)
{
	gsize len							= 0;
	guchar *tmp							= g_base64_decode((char *)keyagent_buffer_data(ptr), &len);
	return keyagent_buffer_alloc(tmp, len);
}

static gboolean
start_session(loadkey_info *info, Json::Value &transfer_data, GError **error)
{
	Json::Value session_data;
    Json::Value session_return_data;
	Json::StreamWriterBuilder builder;

	GPtrArray *headers					= NULL;

	keyagent_buffer_ptr return_data	    = NULL;
	keyagent_buffer_ptr protected_swk   = NULL;
	keyagent_buffer_ptr challenge		= NULL;

	GString *post_data					= NULL;
	GString *session_url				= NULL;
	GString *session_method				= NULL;
	GString *challenge_type				= NULL;
	GString *session_challenge			= NULL;

	long res_status						= -1;
	gboolean ret_status					= FALSE;

	try
	{
		session_url			     		= g_string_new(get_json_value(transfer_data["link"]["challenge-replyto"], (const char *)"href").c_str());
		session_method		     		= g_string_new(get_json_value(transfer_data["link"]["challenge-replyto"], (const char *)"method").c_str());
		challenge_type		     		= g_string_new(get_json_value(transfer_data, (const char *)"challenge_type").c_str());
		session_challenge	     		= g_string_new(get_json_value(transfer_data, (const char *)"challenge").c_str());
	}
	catch(exception& e)
	{
		k_critical_msg("%s\n", e.what());
		goto cleanup;
	}

	//k_debug_msg("Session url:%s\n", session_url->str);

	headers								= g_ptr_array_new ();
	g_ptr_array_add (headers, (gpointer) "Accept: application/octet-stream");
	g_ptr_array_add (headers, (gpointer) "Content-Type: application/json");


	if (strcmp(session_method->str, "post") != 0)
		goto cleanup;

	if (!keyagent_stm_get_challenge(challenge_type->str, &challenge, error))
		goto cleanup;

	keyagent_debug_with_checksum("NPM:CHALLENGEl:REAL", keyagent_buffer_data(challenge), keyagent_buffer_length(challenge));

	return_data							= keyagent_buffer_alloc(NULL,0);
	session_data["challenge-type"]		= challenge_type->str;//keyagent_get_module_label(info->stm);
	session_data["challenge"]			= session_challenge->str;//transfer_data["challenge"];
	session_data["quote"]				= g_base64_encode(keyagent_buffer_data(challenge), keyagent_buffer_length(challenge));

    builder.settings_["indentation"]	= "";
    post_data							= g_string_new(Json::writeString(builder, session_data).c_str());
	res_status							= keyagent_curlsend(session_url, headers, post_data, return_data, 
			                                                    &kms_npm::ssl_opts, kms_npm::debug);
	if (res_status == -1)
	{
		g_error("%s failed", session_url->str);
		goto cleanup;
	}

    if (res_status != 201) 
		goto cleanup;

	protected_swk						= decode_base64_data(return_data);
	info->session						= keyagent_session_create(challenge_type->str, protected_swk, -1, error);
	ret_status							= info->session ? TRUE : FALSE;
	goto cleanup;

cleanup:
	k_string_free(post_data, TRUE);
	k_string_free(session_url, TRUE);
	k_string_free(session_method, TRUE);
	k_string_free(session_challenge, TRUE);
	g_ptr_array_free(headers, TRUE);
	keyagent_buffer_unref(challenge);
	keyagent_buffer_unref(return_data);
	return ret_status;
}

static gboolean
__npm_loadkey(loadkey_info *info, GError **err)
{

	if (info->tries > 1)
	{
        k_set_error (err, KMS_NPM_ERROR_LOAD_KEY,
            "%s: %s", __func__, "NPM Load Key tried more than once\n");
		return FALSE;
	}
	info->tries						   += 1;

	Json::Value transfer_data;
	keyagent_keytype keytype; 

	gboolean ret						= FALSE;
	long res_status						= -1;

	GPtrArray *headers					= NULL;

	keyagent_buffer_ptr return_data		= NULL;
	keyagent_attributes_ptr attrs		= NULL;
	
	GString *accept_challenge_header	= NULL;
	GString *stm_names					= NULL;
	GString *url						= NULL;

	std::string status;
	std::string type;	  

	stm_names							= keyagent_stm_get_names();
	url									= g_string_new(kms_npm::server_url->str);
	g_string_append(url, "/v1/kms/keys/transfer/");

	headers								= g_ptr_array_new ();
	g_ptr_array_add (headers, (gpointer) "Accept: application/json");
	g_ptr_array_add (headers, (gpointer) "Content-Type: application/json");

    if (!info->session) {
		accept_challenge_header			= g_string_new("Accept-Challenge: "); 
		g_string_append(accept_challenge_header, stm_names->str);
		g_ptr_array_add(headers, (gpointer) accept_challenge_header->str);
	}

	return_data							= keyagent_buffer_alloc(NULL,0);
	res_status							= keyagent_curlsend(url, headers, NULL, return_data, &kms_npm::ssl_opts, kms_npm::debug);

	if (res_status == -1)
	{
		g_error("%s failed", url->str);
		goto cleanup;
	}

	transfer_data						= parse_data(return_data);
	//k_debug_msg("res_status %d\n%s", res_status, transfer_data.toStyledString().c_str());

	if (res_status == 401) {
		try {
			status						= get_json_value(transfer_data, (const char *)"status");
			type						= get_json_value(transfer_data["faults"], (const char *)"type");
        } catch (exception& e){
				k_critical_msg("%s\n", e.what());
				goto cleanup;
				//return FALSE;
		}

		if (status == "failure" && type == "not-authorized") {
			if (start_session(info, transfer_data, err))
				ret						= __npm_loadkey(info, err);
		}

	} else if ((res_status & 200) == 200) {

		attrs							= keyagent_attributes_alloc();
		try {
			keytype						= ( get_json_value(transfer_data["data"], "algorithm") == "RSA" ? KEYAGENT_RSAKEY : KEYAGENT_ECCKEY);
			SET_KEY_ATTR(transfer_data["data"], attrs, "payload", KEYDATA);
			SET_KEY_ATTR(transfer_data["data"], attrs, "IV", IV);
			SET_KEY_ATTR(transfer_data["data"], attrs, "STM_DATA", STM_DATA);
            SET_KEY_ATTR(transfer_data["data"], attrs, "STM_TEST_DATA", STM_TEST_DATA);
            SET_KEY_ATTR(transfer_data["data"], attrs, "STM_TEST_SIG", STM_TEST_SIG);
        } catch (exception& e){
				k_critical_msg("%s\n", e.what());
                return FALSE;
		}
		ret = (keyagent_key_create(info->url, keytype, attrs, info->session, -1, err) != NULL ? TRUE : FALSE);
	}
	goto cleanup;

cleanup:
	k_string_free(accept_challenge_header, TRUE);
	k_string_free(stm_names, TRUE);
	k_string_free(url, TRUE);
	keyagent_buffer_unref(return_data);
	g_ptr_array_free(headers, TRUE);
	return ret;
}

extern "C" const char * 
npm_init(const char *config_directory, GError **err)
{
	g_return_val_if_fail( ((err || (err?*err:NULL)) && config_directory), NULL );
	void *config						= NULL;
	gchar *server						= NULL;
	gboolean ret						= TRUE;
	int err_flag						= FALSE;
	const char *retval;


	kms_npm::configfile					= g_string_new(g_build_filename(config_directory, "kms_npm.ini", NULL));
	config								= key_config_openfile(kms_npm::configfile->str, err);
	if (*err)
	{ 
		err_flag						= TRUE;
		npm_finalize(err);
		goto cleanup;
	}
	server								= key_config_get_string(config, "core", "server", err);
	if (*err) {
		err_flag						= TRUE;
		npm_finalize(err);
		goto cleanup;
	}
	kms_npm::server_url					= g_string_new(server);
	kms_npm::debug						= key_config_get_boolean_optional(config, "core", "debug", FALSE);

	memset(&kms_npm::ssl_opts, 0, sizeof (keyagent_curl_ssl_opts));
	kms_npm::certfile					= g_string_new(NULL);
	kms_npm::keyname					= g_string_new(NULL);

	ret									= keyagent_get_certificate_files(kms_npm::certfile, kms_npm::keyname, err);
	if (*err) {
		err_flag						= TRUE;
		npm_finalize(err);
		goto cleanup;
	}
	kms_npm::ssl_opts.certfile			= kms_npm::certfile->str;
	kms_npm::ssl_opts.keyname			= kms_npm::keyname->str;
	kms_npm::ssl_opts.certtype			= "PEM";
    kms_npm::ssl_opts.keytype			= "PEM";
	//k_debug_msg("KMS init completed\n");
	goto cleanup;

cleanup:
	//k_debug_msg("clean up\n");
	key_config_closefile(config);
	return (err_flag)?NULL:"KMS";
}

extern "C" void
npm_finalize(GError **err)
{
	//TODO free up resource on error case
	k_debug_msg("NPM Finalize\n");
	k_string_free(kms_npm::configfile, TRUE);
	k_string_free(kms_npm::server_url, TRUE);
	k_string_free(kms_npm::certfile, TRUE);
	k_string_free(kms_npm::keyname, TRUE);
}

extern "C" gboolean
npm_register(keyagent_url url, GError **err)
{
	g_return_val_if_fail(url, FALSE );
	return TRUE;
}

extern "C" gboolean
npm_key_load(keyagent_url url, GError **err)
{
	
	g_return_val_if_fail( url, FALSE );
    loadkey_info info					= {0, NULL, NULL};
    info.url							= url;
    info.session						= keyagent_session_lookup("SW");
	gboolean ret						= __npm_loadkey(&info, err);
	return ret;
}
