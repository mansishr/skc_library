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
	gboolean policy_support				= FALSE;
	GString *certfile					= NULL;
	GString *keyname					= NULL;
	keyagent_curl_ssl_opts ssl_opts;
}

std::string get_json_value(Json::Value value, const char *key)
{
    char exceptstr[64]					= "Error in parsing json key:";
    if( !value.isMember(key))
    {
        strcat(exceptstr, key);
		throw std::runtime_error(exceptstr);
	}
    return value[key].asString();
}

void get_session_id_from_header(gpointer data, gpointer user_data)
{
    gchar *str                          = (gchar *)data;
	gchar ***tokens_ptr                 = (gchar ***)user_data;
    gchar **tokens                      =  NULL;
    if ( g_str_has_prefix (str,"Session-ID:") == TRUE )
    {
        tokens                          = g_strsplit_set (str,":",-1);
		*tokens_ptr                     = tokens;
        return;
    }
}

gboolean keyagent_key_validate_usage_policy(GTimeVal *policy, const gchar* policy_type){
	GTimeVal ctime;
	gint status                         = -1;
	gboolean ret						= FALSE;
	GDateTime *policy_time              = NULL;
	GDateTime *current_time             = NULL;

	policy_time							= g_date_time_new_from_timeval_local (policy);
	if (policy_time == NULL)
	{
		k_critical_msg("Error in converting date time struct\n");
		return ret;
	}
    g_get_current_time (&ctime);
    current_time                        = g_date_time_new_from_timeval_local (&ctime);
	status                              = g_date_time_compare(policy_time, current_time);
	if ( (strcmp(policy_type, "NOT_AFTER") ==0  && (status == 1)) || 
	   ( (strcmp(policy_type, "NOT_BEFORE") == 0 || strcmp(policy_type, "CREATED_AT") == 0 ) && (status == -1) ))
	{
		ret                             = TRUE;
	}
	g_date_time_unref(policy_time);
	g_date_time_unref(current_time);
	return ret;
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
		const char *val					= json_val.c_str();
		gsize len						= 0;
		guchar *tmp						= g_base64_decode(val, &len);
		return keyagent_buffer_alloc(tmp, len);
	} catch (exception  e) {
		k_critical_msg("%s\n", e.what());
		//throw e;
	}
	return keyagent_buffer_alloc(NULL, 0);
}

static keyagent_policy_buffer_ptr
get_time_val_from_json( Json::Value json_data, const char *name )
{
	keyagent_policy_buffer_ptr \
		policy_attr                     = NULL;
	try {
		std::string	json_val			= get_json_value(json_data, name);
		policy_attr                     = keyagent_policy_buffer_alloc();
		gboolean ret                    = g_time_val_from_iso8601((const gchar *) json_val.c_str(), 
				                                              keyagent_policy_buffer_data(policy_attr));
		k_debug_msg("KEY POLICY %s: %s\n", name, json_val.c_str());
		if( ret == FALSE )
		{
			k_critical_msg("Invalid time stamp information:%s\n", json_val.c_str());
			return NULL;
		}
		return policy_attr;
	} catch (exception  e) {
		k_critical_msg("%s\n", e.what());
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
	GString *swktype					= NULL;
	GString *session_method				= NULL;
	GString *challenge_type				= NULL;
	GString *session_id					= NULL;
	GString *status						= NULL;

	GQuark swk_quark					= 0;
	gsize len							= 0;
	long res_status						= -1;
	gboolean ret_status					= FALSE;

	try
	{
		session_url			     		= g_string_new(get_json_value(transfer_data["link"]["challenge-replyto"],(const char *)"href").c_str());
		session_method		     		= g_string_new(get_json_value(transfer_data["link"]["challenge-replyto"],(const char *)"method").c_str());
		challenge_type		     		= g_string_new(get_json_value(transfer_data, (const char *)"challenge_type").c_str());
		session_id						= g_string_new(get_json_value(transfer_data, (const char *)"challenge").c_str());
	}
	catch(exception& e)
	{
		k_critical_msg("%s\n", e.what());
		goto cleanup;
	}

	headers								= g_ptr_array_new ();
	g_ptr_array_add (headers, (gpointer) "Accept: application/json");
	g_ptr_array_add (headers, (gpointer) "Content-Type: application/json");


	if (strcmp(session_method->str, "post") != 0)
		goto cleanup;

	if (!keyagent_stm_get_challenge(challenge_type->str, &challenge, error))
		goto cleanup;

	keyagent_debug_with_checksum("NPM:CHALLENGEl:REAL", keyagent_buffer_data(challenge), keyagent_buffer_length(challenge));

	return_data							= keyagent_buffer_alloc(NULL,0);
	session_data["challenge_type"]		= challenge_type->str;
	session_data["challenge"]			= session_id->str;
	session_data["quote"]				= g_base64_encode(keyagent_buffer_data(challenge), keyagent_buffer_length(challenge));
	session_data["certificate_chain"]   = "";//TODO need to fill

    builder.settings_["indentation"]	= "";
    post_data							= g_string_new(Json::writeString(builder, session_data).c_str());
	res_status							= keyagent_curlsend(session_url, headers, post_data, NULL, return_data, 
			                                                    &kms_npm::ssl_opts, kms_npm::debug);
	if (res_status == -1)
	{
		g_error("%s failed", session_url->str);
		goto cleanup;
	}

    if (res_status != 201) 
	{
		k_critical_msg("Invalid response:%d\n", res_status);
		goto cleanup;
	}

	session_return_data					= parse_data(return_data);
	json_print(session_return_data);
	try
	{
		session_url			     		= g_string_new(get_json_value(session_return_data,(const char *)"status").c_str());
		protected_swk                   = decode64_json_attr(session_return_data["data"], "swk");
		swktype							= g_string_new(get_json_value(session_return_data["data"],(const char *)"type").c_str());
	}
	catch(exception& e)
	{
		k_critical_msg("%s\n", e.what());
		goto cleanup;
	}

	ret_status							= keyagent_session_create(
																	challenge_type->str,
																	(const char*)g_base64_decode(session_id->str, &len), 
																	protected_swk,
																	(const char *)swktype->str, 
																	-1, 
																	error);
	if( ret_status  == FALSE)
	{
		k_critical_msg("Session create error\n");
		goto cleanup;
	}
	goto cleanup;

cleanup:
	k_string_free(post_data, TRUE);
	k_string_free(session_url, TRUE);
	k_string_free(swktype, TRUE);
	k_string_free(session_method, TRUE);
	k_string_free(session_id, TRUE);
	k_string_free(status, TRUE);
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
	GPtrArray *policy_headers			= NULL;
	GPtrArray *res_headers				= NULL;

	keyagent_session *session			= NULL;

	keyagent_buffer_ptr return_data		= NULL;
	keyagent_buffer_ptr policy_ret_data	= NULL;

	keyagent_attributes_ptr attrs		= NULL;
	keyagent_attributes_ptr policy_attrs= NULL;
	
	GString *accept_challenge_header	= NULL;
	GString *session_ids_header			= NULL;
	GString *stm_names					= NULL;
	GString *session_ids				= NULL;
	GString *url						= NULL;
	GString *policy_url					= NULL;

	std::string status;
	std::string session_id_str;
	std::string type;	  
	std::string key_id_str;	  

	gchar **url_tokens                  = NULL;
	gchar **session_id_tokens           = NULL;
    gchar *session_id                   = NULL;
	
	url_tokens							= g_strsplit (info->url, ":", -1) ;
	stm_names							= keyagent_stm_get_names();
	session_ids							= keyagent_session_get_ids();

	url									= g_string_new(kms_npm::server_url->str);
	g_string_append(url, "/keys/");
	g_string_append(url, url_tokens[1]);
	g_string_append(url, "/transfer/");

	headers								= g_ptr_array_new ();
	g_ptr_array_add (headers, (gpointer) "Accept: application/json");
	g_ptr_array_add (headers, (gpointer) "Content-Type: application/json");

	accept_challenge_header				= g_string_new("Accept-Challenge: "); 
	g_string_append(accept_challenge_header, stm_names->str);
	g_ptr_array_add(headers, (gpointer) accept_challenge_header->str);

    
	if( session_ids != NULL && session_ids->len > 0 )
	{
		session_ids_header				= g_string_new("Session-ID: "); 
		g_string_append(session_ids_header, session_ids->str);
		g_ptr_array_add(headers, (gpointer) session_ids_header->str);
	}


	return_data							= keyagent_buffer_alloc(NULL,0);
	res_headers							= g_ptr_array_new ();
	res_status							= keyagent_curlsend(url, headers, NULL, res_headers, return_data, 
			                                                 &kms_npm::ssl_opts, kms_npm::debug);

	if (res_status == -1)
	{
		g_error("%s failed ...", url->str);
		goto cleanup;
	}

	transfer_data						= parse_data(return_data);
	json_print(transfer_data);

	if (res_status == 401) {
		try {
			status						= get_json_value(transfer_data, (const char *)"status");
			type						= get_json_value(transfer_data["faults"], (const char *)"type");
        } catch (exception& e){
				k_critical_msg("%s\n", e.what());
				goto cleanup;
		}

		if (status == "failure" && type == "not-authorized") {
			if (start_session(info, transfer_data, err) == TRUE)
				ret						= __npm_loadkey(info, err);
		}

	} else if (res_status == 200) {

		attrs							= keyagent_attributes_alloc();
		g_ptr_array_foreach (res_headers, get_session_id_from_header,  &session_id_tokens);

		try {
			key_id_str				    = get_json_value(transfer_data["data"], "id");
			keytype						= ( get_json_value(transfer_data["data"], "algorithm") == "RSA" ? KEYAGENT_RSAKEY : KEYAGENT_ECKEY);
			SET_KEY_ATTR(transfer_data["data"], attrs, "payload", KEYDATA);
            SET_KEY_ATTR(transfer_data["data"], attrs, "STM_TEST_DATA", STM_TEST_DATA);
            SET_KEY_ATTR(transfer_data["data"], attrs, "STM_TEST_SIG", STM_TEST_SIG);
			policy_url					= g_string_new(get_json_value(transfer_data["data"]["policy"]["link"]["key-usage"], "href").c_str());
        } catch (exception& e){
				k_critical_msg("%s\n", e.what());
				goto cleanup;
		}

		if( session_id_tokens == NULL)
		{
			k_critical_msg("Session information not present\n");
			goto cleanup;
		}
		session_id                      = g_strstrip(session_id_tokens[1]);
		if (session_id == NULL)
		{
			k_critical_msg("Session data not found for stm label:%s\n", session_id_tokens[1]);
			goto cleanup;
		}
		if( policy_url != NULL && kms_npm::policy_support == TRUE )
		{
			policy_headers				= g_ptr_array_new ();
			g_ptr_array_add (policy_headers, (gpointer) "Accept: application/json");
			g_ptr_array_add (policy_headers, (gpointer) "Content-Type: application/json");

			policy_ret_data				= keyagent_buffer_alloc(NULL,0);
			res_status					= keyagent_curlsend(policy_url, policy_headers, NULL, NULL, policy_ret_data, 
			                                                 &kms_npm::ssl_opts, kms_npm::debug);
			if( res_status != 200)
			{			
				k_set_error(err, NPM_ERROR_LOAD_KEY, "Error in policy fetching\n");
				goto cleanup;
			}
			transfer_data				= parse_data(policy_ret_data);

			try {

				policy_attrs			= keyagent_attributes_alloc();
				SET_KEY_POLICY_ATTR(transfer_data["data"], policy_attrs, "not_after", NOT_AFTER);
				SET_KEY_POLICY_ATTR(transfer_data["data"], policy_attrs, "not_before", NOT_BEFORE);
				SET_KEY_POLICY_ATTR(transfer_data["data"], policy_attrs, "created_at", CREATED_AT);
		        if( keyagent_key_create(info->url, keytype, attrs, session_id, -1, err) )
				    ret					= keyagent_key_policy_add(info->url, policy_attrs, -1, err);
			}catch(exception& e){
				k_critical_msg("%s\n", e.what());
				goto cleanup;
			}

		}
		else
		{
			ret							= (keyagent_key_create(info->url, keytype, attrs, session_id, -1, err) ? TRUE : FALSE);
		}
	}
	goto cleanup;

cleanup:
	g_strfreev(url_tokens);
	g_strfreev(session_id_tokens);
	k_string_free(accept_challenge_header, TRUE);
	k_string_free(session_ids_header, TRUE);
	k_string_free(stm_names, TRUE);
	k_string_free(session_ids, TRUE);
	k_string_free(url, TRUE);
	k_string_free(policy_url, TRUE);
	keyagent_buffer_unref(return_data);
	keyagent_buffer_unref(policy_ret_data);
	g_ptr_array_free(headers, TRUE);
	if( policy_headers )
		g_ptr_array_free(policy_headers, TRUE);
	g_ptr_array_free(res_headers, TRUE);
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
	kms_npm::policy_support             = key_config_get_boolean_optional(config, "core", "policy_support", FALSE); 

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
	goto cleanup;

cleanup:
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
	gchar **url_tokens                  = NULL;
	gboolean ret						= FALSE;
	
	url_tokens							= g_strsplit (url, ":", -1) ; 
	if ( url_tokens[0] ==  NULL || (g_strcmp0(url_tokens[0], KMS_PREFIX_TOKEN) != 0) || !url_tokens[1])
    {
		if( err )
		{
			k_set_error(err,NPM_ERROR_REGISTER, "NPM_URL_UNSUPPORTED:Expected token:%s token missing in url:%s\n", 
			KMS_PREFIX_TOKEN, url);
		}
		goto cleanup;
    }
	ret									= TRUE;
	k_debug_msg("%s NPM Registered successfully...\n", KMS_PREFIX_TOKEN);
	goto cleanup;

	cleanup:
    	g_strfreev(url_tokens);
		return ret;

}

extern "C" gboolean
npm_key_load(keyagent_url url, GError **err)
{
	
	g_return_val_if_fail( url, FALSE );
    loadkey_info info					= {0, NULL, NULL};
    info.url							= url;
	gboolean ret						= __npm_loadkey(&info, err);
	return ret;
}
