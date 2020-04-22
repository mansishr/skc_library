#define G_LOG_DOMAIN "stm-sgx"
#include <unistd.h>
#include <sgx_capable.h>
#include <sgx_pce.h>
#include "config-file/key_configfile.h"
#include "internal.h"

namespace sgx_application_sgx_stm {
	GString *configfile;
	gboolean debug;
	const char *attestation_type;
	const char* qlPolicy;
}

__attribute__ ((visibility("default")))
const char *
stm_init(const char *config_directory, stm_mode mode, GError **err)
{
	application_stm_init(config_directory, err);

	if(*err) {
		k_critical_error(*err);
		return NULL;
	}
	return "SGX";
}

extern "C" void
application_stm_init(const char *config_directory, GError **err)
{
	void *config = NULL;
	gint  init_delay = 0;
	char *tmp = NULL;

	g_return_if_fail(((err || (err?*err:NULL)) && config_directory));

	sgx_application_sgx_stm::configfile = g_string_new(g_build_filename(config_directory, "sgx_stm.ini", NULL));
	config = key_config_openfile(sgx_application_sgx_stm::configfile->str, err);
	if(*err)
		return;

	sgx_application_sgx_stm::debug = key_config_get_boolean_optional(config, "core", "debug", false);
	sgx_application_sgx_stm::attestation_type = key_config_get_string(config, "core", "type", err);
	if(*err)
		return;

	if(strcmp(sgx_application_sgx_stm::attestation_type, "ECDSA") == 0) {
		sgx_application_sgx_stm::qlPolicy = key_config_get_string(config, "ECDSA", "launch_policy", err);
		if(*err)
			return;
	}
	else {
		k_critical_msg("invalid attestaion type");
		return;
	}

	init_delay = key_config_get_integer_optional(config, "testing", "initdelay", 0);
	if(init_delay)
		sleep(init_delay);
}

extern "C" gboolean
application_stm_activate(GError **err)
{
	gboolean ret = FALSE;
	sgx_status_t sgx_status;
	sgx_device_status_t sgx_device_status;

	sgx_status = sgx_cap_enable_device(&sgx_device_status);

	if(sgx_status == SGX_SUCCESS) {
		switch(sgx_device_status) {
			case SGX_DISABLED_REBOOT_REQUIRED:
				k_info_msg("SGX will be enabled on next reboot");
				k_set_error(err, STM_ERROR_API_MODULE_LOADKEY, "reboot to enable sgx");
				break;
			case SGX_DISABLED_UNSUPPORTED_CPU:
			case SGX_DISABLED:
			case SGX_DISABLED_LEGACY_OS:
				k_critical_msg("SGX is not available");
				k_set_error(err, STM_ERROR_API_MODULE_LOADKEY, "sgx not available");
				break;
			case SGX_ENABLED:
				ret = TRUE;
				break;
			}
	}
	else {
		k_critical_msg("SGX is not available or cannot be enabled");
		k_set_error(err, STM_ERROR_API_MODULE_LOADKEY, "sgx not available");
	}
	return ret;
}

__attribute__ ((visibility("default")))
gboolean
stm_create_challenge(keyagent_stm_create_challenge_details *details, GError **err)
{
	gboolean ret = FALSE;
	struct keyagent_sgx_challenge_request sgx_challenge_request;

	if(!details->apimodule_get_challenge_cb) {
		k_set_error(err, STM_ERROR_API_MODULE_LOADKEY, "invalid apimodule");
		return FALSE;
	}

	if(strcmp(sgx_application_sgx_stm::qlPolicy, "PERSISTENT") == 0) {
		sgx_challenge_request.launch_policy = SGX_QL_PERSISTENT;
	} else if(strcmp(sgx_application_sgx_stm::qlPolicy, "EPHEMERAL") == 0) {
		sgx_challenge_request.launch_policy = SGX_QL_EPHEMERAL;
	} else {
		sgx_challenge_request.launch_policy = SGX_QL_DEFAULT;
		k_critical_msg("invalid launch poilcy provided in config");
		k_set_error(err, STM_ERROR_API_MODULE_LOADKEY, "invalid launch policy");
		return FALSE;
	}
	sgx_challenge_request.attestationType = strdup(sgx_application_sgx_stm::attestation_type);

	ret = (*details->apimodule_get_challenge_cb)(&details->apimodule_details, &sgx_challenge_request, err);

	free((void *)sgx_challenge_request.attestationType);
	
	if(!details->apimodule_details.challenge && !*err) {
		k_set_error(err, STM_ERROR_API_MODULE_LOADKEY, "no challenge returned from api-module");
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
		k_set_error(error, STM_ERROR_API_MODULE_LOADKEY, "invalid apimodule");
		return FALSE;
	}
	ret = (*details->apimodule_load_key_cb)(&details->apimodule_details, NULL, error);
out:
	return ret;
}
