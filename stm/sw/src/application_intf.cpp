#define G_LOG_DOMAIN "stm-sw"
#include "internal.h"

extern "C" const char *
stm_init(const char *config_directory, GError **err)
{
	return "SW";
}

__attribute__ ((visibility("default")))
gboolean
stm_create_challenge(keyagent_stm_create_challenge_details *details, GError **err)
{
	gboolean ret = FALSE;

	if(!details->apimodule_get_challenge_cb) {
		k_critical_msg("apimodule get_challenge cb not set");
		k_set_error(err, STM_ERROR_API_MODULE_LOADKEY, "invalid apimodule");
		return FALSE;
	}

	ret = (*details->apimodule_get_challenge_cb)(&details->apimodule_details, NULL, err);
	
	if(!details->apimodule_details.challenge && !*err) {
		k_critical_msg("no challenge returned from api-module");
		k_set_error(err, STM_ERROR_API_MODULE_LOADKEY, 
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
	if(!details->set_wrapping_key_cb) {
		k_critical_msg("apimodule set_wrapping cb not set");
		k_set_error(err, STM_ERROR_API_MODULE_LOADKEY, "invalid apimodule");
		return FALSE;
	}
	ret = (*details->set_wrapping_key_cb)(&details->apimodule_details, NULL, err);
	return ret;
}

__attribute__ ((visibility("default")))
gboolean
stm_load_key(keyagent_stm_loadkey_details *details, GError **error)
{
	gboolean ret = FALSE;
	if(!details->apimodule_load_key_cb) {
		k_critical_msg("apimodule load_key cb not set");
		k_set_error(error, STM_ERROR_API_MODULE_LOADKEY, "invalid apimodule");
		return FALSE;
	}
	ret = (*details->apimodule_load_key_cb)(&details->apimodule_details, NULL, error);
	return ret;
}
