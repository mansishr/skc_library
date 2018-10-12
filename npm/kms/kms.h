#ifndef _KMS_H_
#define _KMS_H_

#include "config-file/key_configfile.h"
#include "k_errors.h"
#include "key-agent/key_agent.h"
#include "key-agent/npm/npm.h"
#include "key-agent/stm/stm.h"

typedef enum {
	KMS_NPM_ERROR_INIT = 1,
	KMS_NPM_ERROR_REGISTER,
	KMS_NPM_ERROR_LOAD_KEY,
} KmsNpmErrors;

typedef struct {
    int tries;
    keyagent_module *stm;
    keyagent_session *session;
	keyagent_url url;
} loadkey_info;

#define SET_KEY_ATTR(DATA, ATTRS, JSON_KEY, NAME) do { \
	keyagent_buffer_ptr NAME = decode64_json_attr(DATA, JSON_KEY); \
	KEYAGENT_KEY_ADD_BYTEARRAY_ATTR((ATTRS), NAME); \
	keyagent_buffer_unref(NAME); \
} while (0)

#define k_string_free(string, flag) { if(string) g_string_free((string), flag); }

#endif
