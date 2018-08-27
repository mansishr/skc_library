#define G_LOG_DOMAIN "keyagent-keyinit"
#include "config-file/key_configfile.h"
#include "internal.h"
#include "k_errors.h"
#include <glob.h>
#include "key-agent/key_agent.h"


using namespace keyagent;

KEYAGENT_DEFINE_KEY_ATTRIBUTES()

extern "C"
void keyagent_key_set_type(keyagent_key *key, keyagent_keytype type, keyagent_key_attributes_ptr attrs)
{
	key->type = type;
	//key->tag_length = tag_length;
	key->attributes = attrs;
}

extern "C"
void keyagent_key_set_stm(keyagent_key *key, keyagent_module *stm)
{
	key->stm = stm;
}
