#define G_LOG_DOMAIN "stm-sgx"
#include "key-agent/key_agent.h"
#include "key-agent/stm/stm.h"
#include "config-file/key_configfile.h"
#include "k_errors.h"
#include <glib.h>
#include <errno.h>
#include "internal.h"

static stm_mode sgx_stm_mode;

__attribute__ ((visibility("default")))
const char *
stm_init(const char *config_directory, stm_mode mode, GError **err)
{
    sgx_stm_mode = mode;
    if (sgx_stm_mode == APPLICATION_STM_MODE)
        application_stm_init(config_directory, err);
    else
        server_stm_init(config_directory, err);

    if (*err) {
		k_critical_error(*err);
		return NULL;
	}
	return "SGX";
}

__attribute__ ((visibility("default")))
gboolean
stm_activate(GError **err)
{
    if (sgx_stm_mode == APPLICATION_STM_MODE)
        application_stm_activate(err);
    else
        server_stm_activate(err);

    if (*err) {
		k_critical_error(*err);
		return FALSE;
	}
	return TRUE;
}
