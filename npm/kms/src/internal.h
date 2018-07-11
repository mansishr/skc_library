#ifndef __KMS_INTERNAL__
#define __KMS_INTERNAL__


#include <glib.h>
#include <errno.h>
#include "key-agent/npm/npm.h"

typedef struct {
	keyagent_npm_key npm_key;
	const char *sc_id;
	const char *slot_id;
	const char *slot_cert;
	const char *slot_key;
} local_reference_key;

#endif
