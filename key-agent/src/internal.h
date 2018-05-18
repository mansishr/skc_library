#ifndef __KEYAGENT_INTERNAL__
#define __KEYAGENT_INTERNAL__

#include <glib.h>
#include <errno.h>
#include "key-agent/npm/npm.h"
#include "key-agent/stm/stm.h"
#include <gmodule.h>

typedef struct {
	gpointer stm_object;
	gpointer npm_object;
} keyagent_key;


typedef enum {
	KEYAGENT_ERROR = 1,
} ErrorClass;

typedef enum {
	KEYAGENT_ERROR_NPMLOAD = 1,
	KEYAGENT_ERROR_KEYINIT,
	KEYAGENT_ERROR_KEYCONF,
	KEYAGENT_ERROR_NPMKEYINIT,
} KeyAgentErrors;

typedef struct {
    GString         *module_name;
    keyagent_npm    npm;
    GModule         *module;
    gint            initialized:1;
	GQueue			*key_queue;
} local_npm;

typedef struct {
    GString         *module_name;
    keyagent_stm    stm;
    GModule         *module;
    gint            initialized:1;
} local_stm;

typedef struct {
	local_npm 			*npm;
	keyagent_npm_key	*npm_key;
} local_key;

typedef struct {
    char *npm_directory;
    char *key_directory;
    GHashTable *npm_hash;
    GHashTable *stm_hash;
} local_key_agent;

extern local_key_agent key_agent;

void load_keys(GError **err);

#endif
