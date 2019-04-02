#define G_LOG_DOMAIN "keyagent-stm"

#include <string>
#include <iostream>
#include <libgen.h>
#include "../src/internal.h"
#include "config-file/key_configfile.h"
#include "k_errors.h"
#include "k_debug.h"
#include "key-agent/stm/stm.h"
#include "key-agent/key_agent.h"


using namespace keyagent;

extern "C" void DLL_LOCAL 
__initialize_stm(gpointer data, gpointer user_data)
{
    GError **err = (GError **)user_data;
    const char *filename = (const char *)data;
    keyagent_stm_real *stm = g_new0(keyagent_stm_real, 1);
    stm->module_name = g_string_new(filename);
    const char *name = NULL;
    GQuark stm_quark = 0;

    g_autoptr(GError) tmp_error = NULL;

    stm->module = g_module_open (stm->module_name->str, G_MODULE_BIND_LAZY);
    if (!stm->module)
    {
        g_set_error (&tmp_error, KEYAGENT_ERROR, KEYAGENT_ERROR_STMLOAD,
                     "%s", g_module_error ());
        goto errexit;
    }
    LOOKUP_STM_INTERFACES(stm, KEYAGENT_ERROR_STMLOAD);

    name = STM_MODULE_OP(stm,init)(keyagent::configdirectory->str, APPLICATION_STM_MODE, &tmp_error);
    if (!name) goto errexit;
    keyagent_set_module_label(stm, name);
    stm_quark = g_quark_from_string(name);
    stm->initialized = 1;
    g_hash_table_insert(keyagent::stm_hash, GINT_TO_POINTER(stm_quark), stm);
    return;
    errexit:
    if (stm->module)
    {
        if (!g_module_close (stm->module))
            g_warning ("%s: %s", filename, g_module_error ());
    }
    stm->module = NULL;
    //g_propagate_error (err, tmp_error);
    k_info_msg ("Error loading stm - %s: %s", filename, tmp_error->message);
    return;
}

DLL_LOCAL void
__show_stms(gpointer key, gpointer data, gpointer user_data)
{
    keyagent_stm_real *stm = (keyagent_stm_real *)data;
    g_print("STM - %s (%s) - %s\n",keyagent_get_module_label(stm),
            (stm->initialized ? "Initialized" : "Failed"),
            stm->module_name->str);
}

extern "C" void DLL_PUBLIC
keyagent_stm_showlist()
{
    g_print("\n");
    g_hash_table_foreach(keyagent::stm_hash, __show_stms, NULL);
}

DLL_LOCAL void
__get_stm_names(gpointer key, gpointer data, gpointer user_data)
{
    keyagent_stm_real *stm = (keyagent_stm_real *)data;
    GString *names = (GString *)user_data;

    if (names->len)
        g_string_append_c(names,',');
    g_string_append(names, keyagent_get_module_label(stm));
}

DLL_LOCAL GString *
__keyagent_stm_get_names()
{
    GString *names = g_string_new(NULL);
    g_hash_table_foreach(keyagent::stm_hash, __get_stm_names, names);
    return names;
}

extern "C" gboolean DLL_LOCAL
__keyagent_stm_get_by_name(const char *name, keyagent_module **module)
{
    g_return_val_if_fail((name && module), FALSE);
    keyagent_stm_real *stm;
    GQuark stm_quark = g_quark_from_string(name);
    if ((stm = (keyagent_stm_real *)g_hash_table_lookup(keyagent::stm_hash, GINT_TO_POINTER(stm_quark))) == NULL)
        return FALSE;
    
    *module = &stm->stm;
    return TRUE;
}

extern "C" gboolean DLL_LOCAL
__keyagent_stm_set_session(const char *request_id, keyagent_session *session, GError **error)
{
    g_return_val_if_fail(session != NULL, FALSE);
    keyagent_stm_real *lstm = NULL;
    keyagent_stm_session_details details;
    keyagent_request *request = NULL;
	gboolean status = FALSE;

    __keyagent_stm_get_by_name(__keyagent_session_get_stmname(session, error), (keyagent_module **)&lstm);

    g_return_val_if_fail(lstm != NULL, FALSE);

    request = (keyagent_request *)g_hash_table_lookup(keyagent::apimodule_loadkey_hash, request_id);
    g_return_val_if_fail(request != NULL, FALSE);

    lstm->session = (keyagent_session_real *)session;
    details.apimodule_details.module_data = request->module_data;
    request->stm_name = lstm->stm.label;
    details.request_id = request_id; 
	details.apimodule_details.label = __keyagent_session_get_stmname(session, error);
    details.apimodule_details.session = session->swk;
    details.apimodule_details.swk_type = __keyagent_session_lookup_swktype(lstm->session->swk_type->str);
	details.set_wrapping_key_cb = keyagent::apimodule_ops.set_wrapping_key;
    status = STM_MODULE_OP(lstm,set_session)(&details, error);
	k_debug_msg("%s:%d %p status %d", __func__, __LINE__, *error, status);

    if (lstm->session)
        k_debug_generate_checksum("CLIENT:SESSION", k_buffer_data(lstm->session->swk), k_buffer_length(lstm->session->swk));

    return status;
}

extern "C" gboolean DLL_LOCAL
__keyagent_stm_get_challenge(const char *request_id, const char *name, k_buffer_ptr *challenge, GError **error)
{
	keyagent_stm_create_challenge_details details;
	gboolean ret = FALSE;
    keyagent_request *request = NULL;

	if( !name || !challenge || !request_id )
	{
        k_set_error (error, STM_ERROR_INVALID_CHALLENGE_DATA,
            "%s: %s", __func__, "Invalid challenge data");
		return FALSE;
	}
    keyagent_stm_real *lstm = NULL;
    __keyagent_stm_get_by_name(name, (keyagent_module **)&lstm);
    request  = (keyagent_request *)g_hash_table_lookup(keyagent::apimodule_loadkey_hash, request_id);
	if( !lstm || !request )
	{
        k_set_error (error, STM_ERROR_INVALID_CHALLENGE_DATA,
            "%s: %s", __func__, "STM not found");
		return FALSE;
	}

    request->stm_name = lstm->stm.label;
    details.request_id = request_id;
	details.apimodule_get_challenge_cb = keyagent::apimodule_ops.get_challenge;
	details.apimodule_details.challenge = NULL;
	details.apimodule_details.label = name;
    details.apimodule_details.module_data = request->module_data;

    ret = STM_MODULE_OP(lstm,create_challenge)(&details, error);

	*challenge = details.apimodule_details.challenge;
	return ret;
}

extern "C" gboolean DLL_LOCAL
__keyagent_stm_challenge_verify(const char *name, k_buffer_ptr quote, k_attribute_set_ptr *challenge_attrs, GError **error)
{
    g_return_val_if_fail(name && quote && challenge_attrs, FALSE);
    keyagent_stm_real *lstm = NULL;
    __keyagent_stm_get_by_name(name, (keyagent_module **)&lstm);
    g_return_val_if_fail(lstm != NULL, FALSE);
    return STM_MODULE_OP(lstm,challenge_verify)(quote, challenge_attrs, error);
}

extern "C" gboolean DLL_LOCAL
__keyagent_stm_load_key(const char *request_id, keyagent_key *_key, GError **error)
{
    gboolean ret = FALSE;
    keyagent_stm_loadkey_details details;
    keyagent_key_real *key = (keyagent_key_real *)_key;
    keyagent_request *request = NULL;
   	k_buffer_ptr iv = NULL;
    k_buffer_ptr wrapped_key = NULL;
    keyagent_keytransfer_t *keytransfer = NULL;
    k_buffer_ptr keydata = NULL;


    g_return_val_if_fail(key, FALSE);
    if (!key->session) {
        k_set_error (error, KEYAGENT_ERROR_KEYINIT,
            "%s: %s", __func__, "The key has no active session");
        return FALSE;
    }
    keyagent_stm_real *lstm = NULL;
    __keyagent_stm_get_by_name(__keyagent_key_get_stmname(_key, error), (keyagent_module **)&lstm);
    request  = (keyagent_request *)g_hash_table_lookup(keyagent::apimodule_loadkey_hash, request_id);

	if( !lstm || !request || !lstm->session ) {
        k_set_error (error, STM_ERROR_INVALID_LOADKEY_DATA,
            "%s: %s", __func__, "STM not found");
		return FALSE;
	}

	KEYAGENT_KEY_GET_BYTEARRAY_ATTR(key->attributes, KEYDATA, keydata);
    keytransfer = (keyagent_keytransfer_t *)k_buffer_data(keydata);
    if (keytransfer->iv_length > 64) {
        k_set_error (error, STM_ERROR_INVALID_LOADKEY_DATA, "invalid iv length");
        return FALSE;
    }
    iv = k_buffer_alloc(k_buffer_data(keydata) + sizeof(keyagent_keytransfer_t),  keytransfer->iv_length);
    wrapped_key = k_buffer_alloc(k_buffer_data(keydata) + sizeof(keyagent_keytransfer_t) +
        keytransfer->iv_length, keytransfer->wrap_size);

    details.apimodule_details.key = wrapped_key;
    details.apimodule_details.iv = iv;
    details.apimodule_details.tag_size = keytransfer->tag_size;

    details.request_id = request_id;
    details.swk_quark = __keyagent_session_lookup_swktype(lstm->session->swk_type->str);
	details.apimodule_details.label = lstm->stm.label->str;
    details.apimodule_details.module_data = request->module_data;
    details.apimodule_details.type = key->type;
    details.apimodule_details.url = strdup(key->url->str);
    details.apimodule_load_key_cb = keyagent::apimodule_ops.load_key;
	ret = STM_MODULE_OP(lstm,load_key)(&details, error);
    free(details.apimodule_details.url);
    return ret;
}
