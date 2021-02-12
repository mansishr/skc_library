#ifndef _KMS_H_
#define _KMS_H_

#include "config-file/key_configfile.h"
#include "key-agent/key_agent.h"
#include "key-agent/npm/npm.h"

typedef struct {
	int tries;
	keyagent_module *stm;
	keyagent_url url;
	keyagent_keyload_details *details;
}loadkey_info;

#define SET_KEY_ATTR(DATA, ATTRS, JSON_KEY, NAME) do { \
	k_buffer_ptr NAME = decode64_json_attr(DATA, JSON_KEY); \
	KEYAGENT_KEY_ADD_BYTEARRAY_ATTR((ATTRS), NAME); \
	k_buffer_unref(NAME); \
}while(0)

#define KMS_PREFIX_TOKEN "KMS"
#define k_string_free(string) {if(string) g_string_free((string), TRUE);}

#endif
