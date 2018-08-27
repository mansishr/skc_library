#define G_LOG_DOMAIN "npm-kms"
#include <glib.h>
#include <errno.h>
#include "config-file/key_configfile.h"
#include "key-agent/types.h"

const char *
npm_init(char *config_directory, GError **err)
{
	return "KMS";
}

gboolean
npm_register(keyagent_url url)
{
	return TRUE;
}


