#define G_LOG_DOMAIN "stm-sgx"
#include "key-agent/key_agent.h"
#include "key-agent/stm/stm.h"
#include "config-file/key_configfile.h"
#include "k_errors.h"
#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <iostream>
#include <memory>
#include "internal.h"

using namespace std;

namespace sgx_application_sgx_stm {
    GString *configfile;
    gboolean debug;
    gboolean linkable_quote;
}

extern "C" void
application_stm_init(const char *config_directory, GError **err)
{
	void *config = NULL;
	gint  init_delay = 0;
	char *tmp = NULL;

    g_return_if_fail( ((err || (err?*err:NULL)) && config_directory));

    sgx_application_sgx_stm::configfile = g_string_new(g_build_filename(config_directory, "sgx_stm.ini", NULL));
    config = key_config_openfile(sgx_application_sgx_stm::configfile->str, err);
	if (*err)
		return;

    sgx_application_sgx_stm::debug = key_config_get_boolean_optional(config, "core", "debug", false);
    sgx_application_sgx_stm::linkable_quote = key_config_get_boolean_optional(config, "qoute", "linkable", false);

    init_delay = key_config_get_integer_optional(config, "testing", "initdelay", 0);
		
    if (init_delay)
        sleep(init_delay);
}

extern "C" gboolean
application_stm_activate(GError **err)
{
    return TRUE;
}

__attribute__ ((visibility("default")))
gboolean
stm_create_challenge(keyagent_stm_create_challenge_details *details, GError **err)
{
	gboolean ret = FALSE;
    struct keyagent_sgx_challenge_request sgx_challenge_request;

	if (!details->apimodule_get_challenge_cb) {
		k_set_error (err, STM_ERROR_API_MODULE_LOADKEY, "invalid apimodule");
		return FALSE;
	}

    sgx_challenge_request.linkable = sgx_application_sgx_stm::linkable_quote;

	ret = (*details->apimodule_get_challenge_cb)(&details->apimodule_details, &sgx_challenge_request, err);
	
	if (!details->apimodule_details.challenge && !*err) {
		k_set_error (err, STM_ERROR_API_MODULE_LOADKEY, 
			"no challenge returned from api-module");
		ret = FALSE;
	}
    return ret;
}

__attribute__ ((visibility("default")))
gboolean
stm_set_session(keyagent_stm_session_details *details, GError **err)
{
    gboolean ret = FALSE;
	if (!details->set_wrapping_key_cb) {
		k_set_error (err, STM_ERROR_API_MODULE_LOADKEY, "invalid apimodule");
		return FALSE;
	}
	ret = (*details->set_wrapping_key_cb)(&details->apimodule_details, NULL, err);
    k_debug_msg("%s: returning %d", __func__, ret);
    return ret;
}

__attribute__ ((visibility("default")))
gboolean
stm_load_key(keyagent_stm_loadkey_details *details, GError **error)
{
    gboolean ret = FALSE;
	if (!details->apimodule_load_key_cb) {
		k_set_error (error, STM_ERROR_API_MODULE_LOADKEY, "invalid apimodule");
		return FALSE;
	}
	ret = (*details->apimodule_load_key_cb)(&details->apimodule_details, NULL, error);
out:
    return ret;
}

__attribute__ ((visibility("default")))
gboolean
stm_seal_key(keyagent_keytype type, k_attributes_ptr attrs, k_buffer_ptr *sealed_data, GError **error)
{
    return FALSE;
}

__attribute__ ((visibility("default")))
gboolean
stm_unseal_key(keyagent_keytype type, k_buffer_ptr sealed_data, k_attributes_ptr *wrapped_attrs, GError **error)
{
    return FALSE;
}
