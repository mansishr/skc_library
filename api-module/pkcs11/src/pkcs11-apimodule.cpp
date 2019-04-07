#define G_LOG_DOMAIN "pkcs11-apimodule"
#include "config.h"
#include "k_errors.h"
#include "k_debug.h"
#include "internal.h"
//#include <string.h>
#include <gmodule.h>
#include <glib.h>

CK_FUNCTION_LIST_PTR func_list = NULL;

#include "config-file/key_configfile.h"
#include "key-agent/key_agent.h"
#include "key-agent/types.h"

gboolean use_token_objects = FALSE;

static gboolean apimodule_get_challenge(keyagent_apimodule_get_challenge_details *, void *, GError **err);
static gboolean apimodule_set_wrapping_key(keyagent_apimodule_session_details *, void *, GError **err);
static gboolean apimodule_load_key(keyagent_apimodule_loadkey_details *, void *, GError **err);
CK_RV apimodule_init(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

GHashTable *apimodule_token_hash = NULL;
GHashTable *apimodule_api_hash = NULL;
GHashTable *module_hash = NULL;

CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    static CK_RV rv = CKR_GENERAL_ERROR;
    static gsize init = 0;
    if (g_once_init_enter (&init)) {
        rv = apimodule_init(ppFunctionList);
        g_once_init_leave (&init, 1);
    }
    return rv;
}

CK_RV
apimodule_unload_module(void *module)
{
    GModule *mod = (GModule *)g_hash_table_lookup(module_hash, (gpointer)module);
    g_return_val_if_fail(mod, CKR_ARGUMENTS_BAD);

	if (g_module_close(mod) < 0)
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

CK_RV
apimodule_load_module(const char *module_name, CK_FUNCTION_LIST_PTR_PTR funcs)
{
    GModule *mod = NULL;
	CK_RV rv, (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);

    rv = CKR_GENERAL_ERROR;
    g_return_val_if_fail(module_name, CKR_GENERAL_ERROR );
    do {
	    mod = g_module_open(module_name, G_MODULE_BIND_LOCAL);
	    if (!mod) {
            k_critical_msg("%s: %s", module_name, g_module_error ());
            break;
        }
        g_hash_table_insert(module_hash, (gpointer)mod, (gpointer)mod);
        if (!g_module_symbol(mod, "C_GetFunctionList", (gpointer *)&c_get_function_list)) {
            k_critical_msg("%s: invalid pkcs11 module", module_name);
            break;
        }
	    rv = c_get_function_list(funcs);
	    if (rv == CKR_OK)
		    return CKR_OK;
		k_critical_msg("C_GetFunctionList failed %lx", rv);
    } while (FALSE);

    if (mod)
	    apimodule_unload_module((void *) mod);
	return rv;
}

CK_RV
apimodule_init(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	int rv = CKR_OK;
    const char *config_filename = NULL;

    apimodule_token_hash = g_hash_table_new(g_str_hash, g_str_equal);
    apimodule_api_hash = g_hash_table_new(g_str_hash, g_str_equal);
    module_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    g_hash_table_insert(apimodule_api_hash, (gpointer)"SW", sw_apimodule_ops);
#ifdef SGXTOOLKIT
    g_hash_table_insert(apimodule_api_hash, (gpointer)"SGX", sgx_apimodule_ops);
#endif
    keyagent_apimodule_ops apimodule_ops;
	memset(&apimodule_ops, 0, sizeof(apimodule_ops));
    apimodule_ops.load_key = apimodule_load_key;
    apimodule_ops.get_challenge = apimodule_get_challenge;
    apimodule_ops.set_wrapping_key = apimodule_set_wrapping_key;

    if ((config_filename = g_getenv("DHSM2_PKCS11_APIMODULE_CONF")) == NULL)
        config_filename = DHSM2_CONF_PATH "/pkcs11-apimodule.ini"; 

    GError *error = NULL;
    void *config = key_config_openfile(config_filename, &error);
    if (!config) {
        k_critical_error(error);
        return CKR_GENERAL_ERROR;
    }

    gboolean debug = key_config_get_boolean_optional(config, "core", "debug", FALSE);
    if (debug)
        setenv("G_MESSAGES_DEBUG", "all", 1);

    const char *keyagent_config_filename =  key_config_get_string(config, "core", "keyagent_conf", &error);
    if (!keyagent_config_filename) {
        k_critical_error(error);
        return CKR_GENERAL_ERROR;
    }

    const char *mode =  key_config_get_string(config, "core", "mode", &error);
    if (!keyagent_config_filename) {
        k_critical_error(error);
        return CKR_GENERAL_ERROR;
    }

    const char *module =  key_config_get_string(config, mode, "module", &error);
    if (!module) {
        k_critical_error(error);
        return CKR_GENERAL_ERROR;
    }

    use_token_objects = key_config_get_boolean_optional(config, mode, "use_token_objects", FALSE);


	if ((rv = apimodule_load_module(module, ppFunctionList)) != CKR_OK)
        return rv;

    func_list = *ppFunctionList;
	k_debug_msg("Loaded: \"%s\"\n", module);
    if (!keyagent_init(keyagent_config_filename, &error)) {
		k_critical_error(error);
		return CKR_GENERAL_ERROR;
    }
    k_debug_msg("keyagent_init is successful !!!");

    if (!keyagent_apimodule_register(&apimodule_ops, &error)) {
        k_critical_msg(error->message);
        return FALSE;
    }
    k_debug_msg("keyagent_apimodule_register is successful !!!");
	return rv;
}

extern "C"
CK_RV __attribute__((visibility("default")))
C_OnDemand_KeyLoad (const char *uri_string)
{
    CK_RV rv = CKR_OK;
    GError *err = NULL;
    gboolean is_present = FALSE;
    gchar* url = NULL;

	apimodule_uri_data uri_data;

    if (!apimodule_uri_to_uri_data(uri_string, &uri_data)) {
    	rv = CKR_ARGUMENTS_BAD;
		goto end;
	}

    // Find and Initialize the token with label, if not present 
    if ((rv = apimodule_findtoken(&uri_data, &is_present)) != CKR_OK)
        goto end;

    // If token present, Check for Object with Token Label, ID present
    // If not, call Keyagent API and create a token
    if (is_present) {
        CK_SESSION_HANDLE hSession = CKR_SESSION_HANDLE_INVALID;
        // Open a new session for the slot/token
        if ((rv = func_list->C_OpenSession(uri_data.slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession)) != CKR_OK) {
            k_debug_msg("C_OpenSession failed!: 0x%x", rv);
            goto end;
        }

        rv = func_list->C_Login(hSession,CKU_USER, (unsigned char*)uri_data.pin->str, uri_data.pin->len);
        if ( (rv != CKR_OK) && (rv != CKR_USER_ALREADY_LOGGED_IN) ) {
            k_debug_msg("C_Login for user failed!: 0x%x", rv);
            func_list->C_CloseSession(hSession);
            goto end;
        }
        // Find Object in the Token
        rv = apimodule_findobject(hSession, &uri_data, &is_present);
        func_list->C_Logout(hSession);
        func_list->C_CloseSession(hSession);
        // If Object/Key label found in Token, return
        if ((rv != CKR_OK) || is_present)
            goto end;
    }

	rv = CKR_ARGUMENTS_BAD;
    if ((url = g_strjoin(":", uri_data.token_label->str, uri_data.key_id->str, uri_data.key_label->str, uri_string, NULL)) != NULL) {
		k_debug_msg("concat url: %s",  url);
		// Call the Key Agent API to get key details 
		if (keyagent_loadkey_with_moduledata(url, (void*)&uri_data, &err)) {
			rv = CKR_OK;
		} else
			k_debug_msg("key not loaded");
		
        g_free(url);
		url = NULL;
	}

end:
    apimodule_uri_data_cleanup(&uri_data);
    return rv;
}

static gboolean 
apimodule_get_challenge(keyagent_apimodule_get_challenge_details *details, void *request, GError **err)
{
    gboolean result							= FALSE;
    keyagent_apimodule_ops *ops				= NULL;
	apimodule_uri_data *data 				= NULL;
    apimodule_token *atoken 				= NULL;

	do {
    	if (!details || !err || !details->label || !details->module_data) {
        	k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		data = (apimodule_uri_data *)details->module_data;

    	if (!data->token_label) {
        	k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		k_debug_msg("%s for %s", __func__, details->label);

    	atoken = lookup_apimodule_token(data->token_label->str);

    	if (!atoken)
        	atoken = init_apimodule_token(data, err);

    	ops = (keyagent_apimodule_ops *)g_hash_table_lookup(apimodule_api_hash, details->label);

    	if (!atoken || !ops) { 
        	k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

        if (ops->get_challenge(details, request, err)) {
		    details->challenge = k_buffer_ref(atoken->challenge);	
            result = TRUE;
        }

    } while(FALSE);

    return result;
}

static gboolean
apimodule_set_wrapping_key(keyagent_apimodule_session_details *details, void *extra, GError **err)
{
    gboolean result							= FALSE;
    keyagent_apimodule_ops *ops				= NULL;
	apimodule_uri_data *data 				= NULL;
    apimodule_token *atoken 				= NULL;

	do {
    	if (!details || !err || !details->module_data) {
        	k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		data = (apimodule_uri_data *)details->module_data;

    	if (!data->token_label) {
        	k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

    	atoken = lookup_apimodule_token(data->token_label->str);
    	ops = (keyagent_apimodule_ops *)g_hash_table_lookup(apimodule_api_hash, details->label);

    	if (!atoken || !ops) { 
        	k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

        if (ops->set_wrapping_key(details, extra, err))
            result = TRUE;

    } while(FALSE);

    return result;
}

static gboolean 
apimodule_load_key(keyagent_apimodule_loadkey_details *details, void *extra, GError **err)
{
    gboolean result							= FALSE;
    keyagent_apimodule_ops *ops				= NULL;
	apimodule_uri_data *data 				= NULL;
    apimodule_token *atoken 				= NULL;

	do {
    	if (!details || !err || !details->module_data) {
        	k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		data = (apimodule_uri_data *)details->module_data;

    	if (!data->token_label) {
        	k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

    	atoken = lookup_apimodule_token(data->token_label->str);
    	ops = (keyagent_apimodule_ops *)g_hash_table_lookup(apimodule_api_hash, details->label);

    	if (!atoken || !ops) { 
        	k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

        if (ops->load_key(details, extra, err))
            result = TRUE;

    } while(FALSE);

    return result;
}
