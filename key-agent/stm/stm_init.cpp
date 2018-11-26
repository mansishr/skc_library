#define G_LOG_DOMAIN "keyagent-stm"

#include <string>
#include <iostream>
#include <libgen.h>
#include "../src/internal.h"
#include "config-file/key_configfile.h"
#include "k_errors.h"
#include "key-agent/stm/stm.h"
#include "key-agent/key_agent.h"


using namespace keyagent;

extern "C" void
initialize_stm(gpointer data, gpointer user_data)
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

static void
show_stms(gpointer key, gpointer data, gpointer user_data)
{
    keyagent_stm_real *stm = (keyagent_stm_real *)data;
    g_print("STM - %s (%s) - %s\n",keyagent_get_module_label(stm),
            (stm->initialized ? "Initialized" : "Failed"),
            stm->module_name->str);
}

extern "C" void
keyagent_stm_showlist()
{
    g_print("\n");
    g_hash_table_foreach(keyagent::stm_hash, show_stms, NULL);
}

static void
get_stm_names(gpointer key, gpointer data, gpointer user_data)
{
    keyagent_stm_real *stm = (keyagent_stm_real *)data;
    GString *names = (GString *)user_data;

    if (names->len)
        g_string_append_c(names,',');
    g_string_append(names, keyagent_get_module_label(stm));
}

extern "C" GString *
keyagent_stm_get_names()
{
    GString *names = g_string_new(NULL);
    g_hash_table_foreach(keyagent::stm_hash, get_stm_names, names);
    return names;
}

extern "C" gboolean
keyagent_stm_get_by_name(const char *name, keyagent_module **module)
{
    g_return_val_if_fail((name && module), FALSE);
    keyagent_stm_real *stm;
    GQuark stm_quark = g_quark_from_string(name);
    if ((stm = (keyagent_stm_real *)g_hash_table_lookup(keyagent::stm_hash, GINT_TO_POINTER(stm_quark))) == NULL)
        return FALSE;
    
    *module = &stm->stm;
    return TRUE;
}

extern "C" gboolean
keyagent_stm_set_session(keyagent_session *session, GError **error)
{
    g_return_val_if_fail(session != NULL, FALSE);
    keyagent_stm_real *lstm = NULL;
    keyagent_stm_get_by_name(keyagent_session_get_stmname(session, error), (keyagent_module **)&lstm);

    g_return_val_if_fail(lstm != NULL, FALSE);

    lstm->session = (keyagent_session_real *)session;
    GQuark swk_quark = keyagent_session_lookup_swktype(lstm->session->swk_type->str);
    STM_MODULE_OP(lstm,set_session)(swk_quark,session->swk, error);

    if (lstm->session)
        keyagent_debug_with_checksum("CLIENT:SESSION", keyagent_buffer_data(lstm->session->swk), keyagent_buffer_length(lstm->session->swk));

    return TRUE;
}

extern "C" gboolean
keyagent_stm_get_challenge(const char *name, keyagent_buffer_ptr *challenge, GError **error)
{
    g_return_val_if_fail(name && challenge, FALSE);
    keyagent_stm_real *lstm = NULL;
    keyagent_stm_get_by_name(name, (keyagent_module **)&lstm);
    g_return_val_if_fail(lstm != NULL, FALSE);
    return STM_MODULE_OP(lstm,create_challenge)(challenge, error);
}

extern "C" gboolean
keyagent_stm_challenge_verify(const char *name, keyagent_buffer_ptr quote, keyagent_attributes_ptr *challenge_attrs, GError **error)
{
    g_return_val_if_fail(name && quote && challenge_attrs, FALSE);
    keyagent_stm_real *lstm = NULL;
    keyagent_stm_get_by_name(name, (keyagent_module **)&lstm);
    g_return_val_if_fail(lstm != NULL, FALSE);
    return STM_MODULE_OP(lstm,challenge_verify)(quote, challenge_attrs, error);
}

extern "C" gboolean
keyagent_stm_load_key(keyagent_key *_key, GError **error)
{
    keyagent_key_real *key = (keyagent_key_real *)_key;
    g_return_val_if_fail(key, FALSE);
    if (!key->session) {
        k_set_error (error, KEYAGENT_ERROR_KEYINIT,
            "%s: %s", __func__, "The key has no active session");
        return FALSE;
    }
    keyagent_stm_real *lstm = NULL;
    keyagent_stm_get_by_name(keyagent_key_get_stmname(_key, error), (keyagent_module **)&lstm);
    g_return_val_if_fail(lstm != NULL || lstm->session != NULL, FALSE);

    GQuark swk_quark = keyagent_session_lookup_swktype(lstm->session->swk_type->str);
	return STM_MODULE_OP(lstm,load_key)(swk_quark, key->type, key->attributes, error);
}
