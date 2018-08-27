#ifndef __KEYAGENT_INTERNAL__
#define __KEYAGENT_INTERNAL__

#include <glib.h>
#include <errno.h>
#include "key-agent/npm/npm.h"
#include "key-agent/stm/stm.h"
#include <gmodule.h>

typedef enum {
	KEYAGENT_ERROR = 1,
} ErrorClass;

typedef enum {
	KEYAGENT_ERROR_NPMLOAD = 1,
	KEYAGENT_ERROR_KEYINIT,
	KEYAGENT_ERROR_KEYCONF,
	KEYAGENT_ERROR_NPMKEYINIT,
	KEYAGENT_ERROR_STMLOAD,
} KeyAgentErrors;

typedef struct {
    keyagent_module npm;
    GString         *module_name;
    GModule         *module;
    gint            initialized:1;
	GQueue			*key_queue;
	npm_ops         ops;
} keyagent_real_npm;

typedef struct {
    keyagent_module  stm;
    GString         *module_name;
    GModule         *module;
    gint            initialized:1;
	keyagent_buffer_ptr		session;
	stm_ops         ops;
} keyagent_real_stm;

typedef struct {
    char *npm_directory;
    char *key_directory;
    GHashTable *npm_hash;
    GHashTable *stm_hash;
} xxlocal_key_agent;


#ifdef  __cplusplus

namespace keyagent {
    extern GString *configdirectory;
	extern GString *configfilename;
	extern void *config;
	extern GString *npm_directory;
	extern GString *stm_directory;
    extern GString *key_directory;
    extern GString *cert;
    extern GString *certkey;
    extern GHashTable *npm_hash;
    extern GHashTable *stm_hash;
}
#endif

#define KEYAGENT_MODULE_LOOKUP(MODULE,FUNCNAME,RET, ERRCLASS) do { \
	if (!g_module_symbol ((MODULE), (FUNCNAME), (gpointer *)&(RET))) \
    { \
		g_set_error (&tmp_error, KEYAGENT_ERROR, (ERRCLASS), \
                   "%s: %s", filename, g_module_error ()); \
		goto errexit; \
    } \
} while (0)

extern "C" void initialize_stm(gpointer data, gpointer user_data);
extern "C" void initialize_npm(gpointer data, gpointer user_data);


#endif
