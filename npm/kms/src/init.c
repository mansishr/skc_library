#define G_LOG_DOMAIN "npm-kms"
#include "internal.h"
#include <glib.h>
#include <errno.h>
#include "config-file/key_configfile.h"

void 
npm_init(keyagent_npm *npm, GError **err)
{
}

keyagent_npm_key *
npm_key_init(keyagent_npm *npm, void *config, GQuark id, GError **err)
{
	g_message("%s - initializing %s\n", npm->name->str, g_quark_to_string(id));
	local_reference_key *key = g_new0(local_reference_key,1);
	if (!key) return NULL;
	
	key->npm_key.id = id;
	key->sc_id = key_config_get_string_optional(config, "key", "sc_id", NULL);
	key->slot_id = key_config_get_string_optional(config, "key", "slot_id", NULL);
	key->slot_cert = key_config_get_string_optional(config, "key", "slot_cert", NULL);
	key->slot_key  = key_config_get_string_optional(config, "key", "slot_key", NULL);
	return g_new0(keyagent_npm_key, 1);
}
