#define G_LOG_DOMAIN "pkcs11-apimodule"
#include <unistd.h>
#include <gmodule.h>
#include "config.h"
#include "k_debug.h"
#include "internal.h"
#include "config-file/key_configfile.h"
extern "C" {
#include "safe_lib.h"
}

CK_RV apimodule_init(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
gboolean apimodule_initialize(keyagent_apimodule_ops *ops, GError **err);

static gboolean apimodule_get_challenge(keyagent_apimodule_get_challenge_details *, void *, GError **err);
static gboolean apimodule_set_wrapping_key(keyagent_apimodule_session_details *, void *, GError **err);
static gboolean apimodule_load_key(keyagent_apimodule_loadkey_details *, void *, GError **err);
static gboolean apimodule_load_uri(const char *uri);
static gboolean apimodule_preload_keys(GError **err);
static CK_RV (*c_initialize)(CK_VOID_PTR pInitArgs);
static CK_RV (*c_finalize)(CK_VOID_PTR pInitArgs);

static char* pre_load_keyfile = NULL;
static const char *loadable_module = NULL;
static char *mode=NULL;

GHashTable *apimodule_token_hash = NULL;
GHashTable *apimodule_api_hash = NULL;
GHashTable *module_hash = NULL;
CK_FUNCTION_LIST_PTR func_list = NULL;
keyagent_apimodule_ops apimodule_ops;

void
apimodule_prepare_child(void)
{
	CK_RV rv = CKR_OK;
	CK_SESSION_HANDLE hSession;
	apimodule_uri_data uri_data;
	gboolean is_present = FALSE;
	FILE *fp = NULL;
	char *uri = NULL;
	size_t len = 0;
	ssize_t read = 0;

	//as we are starting in a new child process, re-initialize the cryptoki/CTK library
	rv = C_Finalize(NULL);
	rv = C_Initialize(NULL);

	if((fp = fopen(pre_load_keyfile, "r")) == NULL) {
		k_critical_msg("apimodule_prepare_child: Could not find file %s", pre_load_keyfile);
		return;
	}

	read = getline(&uri, &len, fp);

	if(read <= 0) {
		k_critical_msg("apimodule_prepare_child: no pkcs11 url found in %s file", pre_load_keyfile);
		goto end;
	}

	if(!apimodule_uri_to_uri_data(uri, &uri_data)) {
		rv = CKR_ARGUMENTS_BAD;
		k_critical_msg("apimodule_prepare_child: apimodule_uri_to_uri_data failed");
		goto end;
	}

	//find the token which was created by the parent process
	if((rv = apimodule_findtoken(&uri_data, &is_present)) != CKR_OK) {
		k_critical_msg("apimodule_prepare_child: %s failed!: 0x%lx\n", "apimodule_findtoken", rv);
		goto end;
	}

	if(is_present) {
		// now that we found the token object, we need to open a session and login into the token
		if((rv = func_list->C_OpenSession(uri_data.slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession)) != CKR_OK) {
			k_critical_msg("apimodule_prepare_child: %s failed!: 0x%lx\n", "C_OpenSession", rv);
			goto end;
		}

		rv = func_list->C_Login(hSession, CKU_USER, (unsigned char*)uri_data.pin->str, uri_data.pin->len);
		if(rv == CKR_USER_ALREADY_LOGGED_IN)
			rv = CKR_OK;

		if(rv != CKR_OK) {
			k_critical_msg("%s failed!: 0x%lx\n", "user C_Login", rv);
			goto end;
		}
	}
	else {
		k_critical_msg("no token object is found. this should not happen");
	}
end:
	if(fp)
		fclose(fp);
	return;
}

CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	static CK_RV rv = CKR_GENERAL_ERROR;
	static gsize init = 0;
	if(g_once_init_enter(&init)) {
		rv = apimodule_init(ppFunctionList);
		if(g_strcmp0(mode, "SGX") == 0) {
			// define a handler which should be called before child process starts executing
			pthread_atfork(NULL, NULL, apimodule_prepare_child);
		}
		g_once_init_leave (&init, 1);
	}
	*ppFunctionList = func_list;
	return rv;
}

CK_RV
C_Initialize(CK_VOID_PTR pInitArgs)
{
	CK_RV ret = -1;
	GError *error = NULL;
	static volatile gint preload_keys_flag = 0;

	ret = c_initialize(pInitArgs);
	if((ret == CKR_OK) || (ret == CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
		if(!g_atomic_int_add(&preload_keys_flag, 1)) {
			if(!apimodule_preload_keys(&error)) {
				k_critical_msg("apimodule_preload_keys failed");
				k_critical_error(error);
			}
		}
	}
	return ret;
}

CK_RV
C_Finalize(CK_VOID_PTR pDummy)
{
	return c_finalize(pDummy);
}

CK_RV
apimodule_unload_module(void *module)
{
	GModule *mod = (GModule *)g_hash_table_lookup(module_hash, (gpointer)module);
	g_return_val_if_fail(mod, CKR_ARGUMENTS_BAD);

	if(g_module_close(mod) < 0)
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

CK_RV
apimodule_load_module(const char *module_name, CK_FUNCTION_LIST_PTR_PTR funcs)
{
	GModule *mod = NULL;
	CK_RV rv, (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);

	rv = CKR_GENERAL_ERROR;
	g_return_val_if_fail(module_name, CKR_GENERAL_ERROR);
	do {
		mod = g_module_open(module_name, G_MODULE_BIND_LOCAL);
		if(!mod) {
			k_critical_msg("%s: %s", module_name, g_module_error());
			break;
		}
		g_hash_table_insert(module_hash, (gpointer)mod, (gpointer)mod);
		if(!g_module_symbol(mod, "C_GetFunctionList", (gpointer *)&c_get_function_list)) {
			k_critical_msg("%s: invalid pkcs11 module", module_name);
			break;
		}
		if((rv = c_get_function_list(funcs)) == CKR_OK) {
			if(g_module_symbol(mod, "C_Initialize", (gpointer *)&c_initialize))
				(*funcs)->C_Initialize = C_Initialize;
			if(g_module_symbol(mod, "C_Finalize", (gpointer *)&c_finalize))
				(*funcs)->C_Finalize = C_Finalize;
			return CKR_OK;
		}
		else {
			k_critical_msg("C_GetFunctionList failed %0xlx, %s", rv, module_name);
		}
	}while(FALSE);

	if(mod)
		apimodule_unload_module((void *) mod);
	return rv;
}

CK_RV __attribute__((visibility("default")))
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
	memset(&apimodule_ops, 0, sizeof(apimodule_ops));
	apimodule_ops.load_key = apimodule_load_key;
	apimodule_ops.get_challenge = apimodule_get_challenge;
	apimodule_ops.set_wrapping_key = apimodule_set_wrapping_key;
	apimodule_ops.init = apimodule_initialize;
	apimodule_ops.load_uri = apimodule_load_uri;

	if((config_filename = g_getenv("SKC_PKCS11_APIMODULE_CONF")) == NULL)
		config_filename = SKC_CONF_PATH "/pkcs11-apimodule.ini";

	GError *error = NULL;
	void *config = key_config_openfile(config_filename, &error);
	if(!config) {
		k_critical_error(error);
		return CKR_GENERAL_ERROR;
	}

	gboolean debug = key_config_get_boolean_optional(config, "core", "debug", FALSE);
	if(debug)
		setenv("G_MESSAGES_DEBUG", "all", 1);

	const char *keyagent_config_filename = key_config_get_string(config, "core", "keyagent_conf", &error);
	if(!keyagent_config_filename) {
		k_critical_error(error);
		return CKR_GENERAL_ERROR;
	}

	mode = key_config_get_string(config, "core", "mode", &error);
	if(!mode) {
		k_critical_error(error);
		return CKR_GENERAL_ERROR;
	}

	loadable_module = key_config_get_string(config, mode, "module", &error);
	if(!loadable_module) {
		k_critical_error(error);
		return CKR_GENERAL_ERROR;
	}

	pre_load_keyfile = key_config_get_string_optional(config, "core", "preload_keys", "NIL");

	if((rv = apimodule_load_module(loadable_module, ppFunctionList)) != CKR_OK)
		return rv;
	func_list = *ppFunctionList;
	k_info_msg("Loaded: \"%s\"\n", loadable_module);
	if(!keyagent_init(keyagent_config_filename, &error)) {
		k_critical_error(error);
		return CKR_GENERAL_ERROR;
	}
	k_info_msg("keyagent_init is successful !!!");

	if(!keyagent_apimodule_register(mode, &apimodule_ops, &error)) {
		k_critical_msg(error->message);
		return FALSE;
	}

	k_info_msg("keyagent_apimodule_register is successful !!!");
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
	apimodule_token *atoken = NULL;
	apimodule_uri_data uri_data;

	if(!apimodule_uri_to_uri_data(uri_string, &uri_data)) {
		rv = CKR_ARGUMENTS_BAD;
		goto end;
	}

	atoken = lookup_apimodule_token(uri_data.token_label->str);
	if(!atoken)
		atoken = init_apimodule_token(&uri_data, FALSE, &err);

	if(atoken) {
		if(g_strcmp0(atoken->pin->str, uri_data.pin->str) != 0)
		{
			k_critical_msg("Pin value mismatch for token:%s and ignoring url:%s", uri_data.token_label->str, uri_string);
			rv = CKR_GENERAL_ERROR;
			goto end;
		}
	rv = apimodule_findobject(atoken->session, &uri_data, &is_present);
	// If Object/Key label found in Token, return
	if((rv != CKR_OK) || is_present)
		goto end;
	}

	rv = CKR_ARGUMENTS_BAD;
	if((url = g_strjoin(":", uri_data.token_label->str, uri_data.key_id->str, uri_data.key_label->str, uri_string, NULL)) != NULL) {
		// Call the Key Agent API to get key details
		if(keyagent_loadkey_with_moduledata(url, (void*)&uri_data, &err)) {
			rv = CKR_OK;
			k_info_msg("key transfer is successful");
		} else
			k_critical_msg("C_OnDemand_KeyLoad: pkcs11 uri values are not correct");

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
	gboolean result = FALSE;
	keyagent_apimodule_ops *ops = NULL;
	apimodule_uri_data *data = NULL;
	apimodule_token *atoken = NULL;

	do {
		if(!details || !err || !details->label || !details->module_data) {
			k_critical_msg("apimodule_get_challenge: input parameters are invalid");
			k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		data = (apimodule_uri_data *)details->module_data;

		if(!data->token_label) {
			k_critical_msg("apimodule_get_challenge: token label not found");
			k_set_error(err, -1, "token label not found");
			break;
		}

		k_debug_msg("%s for %s", __func__, details->label);

		atoken = lookup_apimodule_token(data->token_label->str);
		if(!atoken)
			atoken = init_apimodule_token(data, TRUE, err);

		ops = (keyagent_apimodule_ops *)g_hash_table_lookup(apimodule_api_hash, details->label);

		if(!atoken || !ops) {
			k_critical_msg("apimodule_get_challenge: token object not found");
			k_set_error(err, -1, "Token Object not found");
			break;
		}

		if(ops->get_challenge(details, request, err)) {
			details->challenge = k_buffer_ref(atoken->challenge);
			result = TRUE;
		}
	}while(FALSE);

	return result;
}

static gboolean
apimodule_set_wrapping_key(keyagent_apimodule_session_details *details, void *extra, GError **err)
{
	gboolean result = FALSE;
	keyagent_apimodule_ops *ops = NULL;
	apimodule_uri_data *data = NULL;
	apimodule_token *atoken = NULL;

	do {
		if(!details || !err || !details->module_data) {
			k_critical_msg("apimodule_set_wrapping_key: input parameters are invalid");
			k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		data = (apimodule_uri_data *)details->module_data;

		if(!data->token_label) {
			k_critical_msg("apimodule_set_wrapping_key: token label not found");
			k_set_error(err, -1, "Token label not found");
			break;
		}

		atoken = lookup_apimodule_token(data->token_label->str);
		ops = (keyagent_apimodule_ops *)g_hash_table_lookup(apimodule_api_hash, details->label);

		if(!atoken || !ops) {
			k_critical_msg("apimodule_set_wrapping_key: token obj not found");
			k_set_error(err, -1, "Token object not found");
			break;
		}

		if(ops->set_wrapping_key(details, extra, err))
			result = TRUE;
	}while(FALSE);

	return result;
}

gboolean __attribute__((visibility("default")))
apimodule_initialize(keyagent_apimodule_ops *ops, GError **err)
{
	gboolean ret = FALSE;
	if(!ops)
	{
		g_set_error(err, APIMODULE_ERROR, APIMODULE_ERROR_INVALID_INPUT, "keyagent_apimodule_ops ptr is null");
		return ret;
	}

	CK_RV rv;
	CK_FUNCTION_LIST_PTR func_list;
	do {
		rv = C_GetFunctionList(&func_list);
		if(rv != CKR_OK)
		{
			g_set_error(err, APIMODULE_ERROR, APIMODULE_ERROR_API_RETURN_ERROR,  "C_GetFunctionList failed !, rv:%0x\n", rv);
			break;
		}
		rv = C_Initialize(NULL);
		if(rv != CKR_OK  && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		{
			g_set_error(err, APIMODULE_ERROR, APIMODULE_ERROR_API_RETURN_ERROR,  "C_Initialize failed !, rv:%0x\n", rv);
			break;
		}
		memcpy_s(ops, sizeof(*ops), &apimodule_ops, sizeof(keyagent_apimodule_ops));
		ret=TRUE;
	}while(FALSE);
	return ret;
}

static gboolean
apimodule_load_uri(const char *uri)
{
	gboolean result = FALSE;
	do {
		if(uri == NULL || g_strcmp0(uri, "") == 0)
		{
			k_critical_msg("Invalid uri:%s\n", uri);
			break;
		}

		if(C_OnDemand_KeyLoad((const char *)uri) != CKR_OK) {
			 k_critical_msg("C_OnDemand_KeyLoad failed for uri:%s\n", uri);
			 break;
		}
		result = TRUE;
	}while(FALSE);
	return result;
}

static gboolean
apimodule_load_key(keyagent_apimodule_loadkey_details *details, void *extra, GError **err)
{
	gboolean result = FALSE;
	keyagent_apimodule_ops *ops = NULL;
	apimodule_uri_data *data = NULL;
	apimodule_token *atoken = NULL;
	do {
		if(!details || !err || !details->module_data) {
			k_critical_msg("apimodule_load_key: input parameters are invalid");
			k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		data = (apimodule_uri_data *)details->module_data;

		if(!data->token_label) {
			k_critical_msg("apimodule_load_key: token label not found");
			k_set_error(err, -1, "Token Label not found");
			break;
		}
		atoken = lookup_apimodule_token(data->token_label->str);
		ops = (keyagent_apimodule_ops *)g_hash_table_lookup(apimodule_api_hash, details->label);

		if(!atoken || !ops) {
			k_critical_msg("apimodule_load_key: token obj info not found");
			k_set_error(err, -1, "token onj info not found");
			break;
		}
		CK_ULONG type = (details->type == KEYAGENT_AESKEY ? CKO_SECRET_KEY : CKO_PRIVATE_KEY);

		if(data->type == CKO_DATA) {
			data->type = type;
		}
		if(data->type != type) {
			k_critical_msg("Incompatible type in uri for key-id:%s", data->key_id->str);
			k_set_error(err, -1, "Incompatible type in uri for key-id:%s", data->key_id->str);
			break;
		}
		if(ops->load_key(details, extra, err))
			result = TRUE;
	}while(FALSE);

	return result;
}

gboolean
apimodule_preload_keys(GError **err)
{
	FILE *fp = NULL;
	char *uri = NULL;
	size_t len = 0;
	ssize_t read = 0;
	gboolean ret = FALSE;

	if(g_strcmp0(pre_load_keyfile, "NIL") == 0) {
		k_critical_msg("preload_keys directive missing in pkcs11-apimodule.ini");
		return ret;
	}

	do {
		if((fp = fopen(pre_load_keyfile, "r")) == NULL) {
			k_critical_msg("could not open preload_keys file specified in pkcs11-apimodule.ini");
			g_set_error(err, APIMODULE_ERROR, APIMODULE_ERROR_INVALID_CONF_VALUE,"Invalid File :%s", __func__);
			break;
		}

		while((read = getline(&uri, &len, fp)) > 0) {
			k_info_msg("loading key: %s", uri);
			if(C_OnDemand_KeyLoad((const char *)uri) != CKR_OK) {
				ret = FALSE;
				if(!*err)
					g_set_error(err, APIMODULE_ERROR, APIMODULE_ERROR_INVALID_CONF_VALUE, "Error while pre-loading key:%s", uri);
				break;
			}
			else {
				ret = TRUE;
			}
		}
	}while(FALSE);

	if(fp)
		fclose(fp);
	if(uri)
		free(uri);
	return ret;
}
