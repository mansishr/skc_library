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
    keyagent_real_stm *stm = g_new0(keyagent_real_stm, 1);
    stm->module_name = g_string_new(filename);
    const char *name = NULL;

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

    stm->initialized = 1;
    g_hash_table_insert(keyagent::stm_hash, keyagent_get_module_label(stm), stm);
    keyagent_stm_set_session((keyagent_module *)stm, NULL);
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
    keyagent_real_stm *stm = (keyagent_real_stm *)data;
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
    keyagent_real_stm *stm = (keyagent_real_stm *)data;
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

extern "C" keyagent_module *
keyagent_stm_get_by_name(const char *name)
{
    keyagent_real_stm *stm = (keyagent_real_stm *)g_hash_table_lookup(keyagent::stm_hash, name);
    return &stm->stm;
}

extern "C" void
keyagent_stm_set_session(keyagent_module *stm, keyagent_buffer_ptr session)
{
    g_autoptr(GError) error = NULL;
    keyagent_real_stm *lstm = (keyagent_real_stm *)stm;
    if (!session) {
       gchar *encoded_session = (gchar *)key_config_get_string(keyagent::config, keyagent_get_module_label(stm), "session", NULL);
       if (!encoded_session) return;
       gsize outlen;
       guchar *decoded_session = g_base64_decode(encoded_session, &outlen);
       lstm->session = keyagent_buffer_alloc((void *)decoded_session, (int)outlen);
       g_free(encoded_session);
    } else {
        lstm->session = keyagent_buffer_ref(session);
        gchar *tmp = g_base64_encode(keyagent_buffer_data(session), keyagent_buffer_length(session));
        g_key_file_set_string((GKeyFile *) keyagent::config, keyagent_get_module_label(stm), "session", tmp);
        if (!g_key_file_save_to_file((GKeyFile *) keyagent::config, keyagent::configfilename->str, &error))
            k_critical_error(error);
        g_free(tmp);
    }

    STM_MODULE_OP(lstm,set_session)(lstm->session);

    if (lstm->session)
        keyagent_debug_with_checksum("CLIENT:SESSION", keyagent_buffer_data(lstm->session), keyagent_buffer_length(lstm->session));

}

extern "C" keyagent_buffer_ptr
keyagent_stm_get_challenge(keyagent_module *stm)
{
    keyagent_real_stm *lstm = (keyagent_real_stm *)stm;
    return STM_MODULE_OP(lstm,create_challenge)();
}

extern "C" keyagent_buffer_ptr
keyagent_stm_challenge_verify(keyagent_module *stm, keyagent_buffer_ptr quote)
{
    keyagent_real_stm *lstm = (keyagent_real_stm *)stm;
    return STM_MODULE_OP(lstm,challenge_verify)(quote);
}

extern "C" keyagent_key_attributes_ptr
keyagent_stm_wrap_key(keyagent_module *stm, keyagent_keytype type, keyagent_key_attributes_ptr key_attrs)
{
    keyagent_real_stm *lstm = (keyagent_real_stm *)stm;
    keyagent_key_attributes_ptr wrapped_attrs = STM_MODULE_OP(lstm,wrap_key)(type, key_attrs);
    return wrapped_attrs;
}


extern "C" gboolean
keyagent_stm_load_key(keyagent_key *key)
{
    keyagent_real_stm *lstm = (keyagent_real_stm *)key->stm;
    gboolean ret = STM_MODULE_OP(lstm,load_key)(key->type, key->attributes);
    return ret;
}
