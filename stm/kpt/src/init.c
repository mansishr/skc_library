#define G_LOG_DOMAIN "stm-kpt"
#include "key-agent/stm/stm.h"
#include <glib.h>
#include <errno.h>

const char *
stm_init(const char *config_directory, stm_mode mode, GError **err)
{
	return "KPT2";
}
