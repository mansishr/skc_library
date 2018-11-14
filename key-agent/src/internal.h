#ifndef __KEYAGENT_INTERNAL__
#define __KEYAGENT_INTERNAL__

#include <glib.h>
#include <errno.h>
#include "key-agent/npm/npm.h"
#include "key-agent/stm/stm.h"
#include <gmodule.h>

typedef struct {
    keyagent_module npm;
    GString         *module_name;
    GModule         *module;
    gint            initialized:1;
	GQueue			*key_queue;
	npm_ops         ops;
} keyagent_npm_real;

typedef struct {
	gint id;
	gint cached:1;
} keyagent_cache_state;

typedef struct {
    keyagent_buffer_ptr		swk;
    GString                 *name;
    GString                 *session_id;
	keyagent_cache_state	cache_state;
} keyagent_session_real;

typedef struct {
    keyagent_module  stm;
    GString         *module_name;
    GModule         *module;
    gint            initialized:1;
	stm_ops         ops;
	keyagent_session_real    *session;
} keyagent_stm_real;

typedef struct {
    GString  *url;
    keyagent_keytype type;
    keyagent_session *session;
    keyagent_attributes_ptr attributes;
    keyagent_cache_state	cache_state;
} keyagent_key_real;

#define DECLARE_KEYAGENT_REAL_PTR(VAR,TYPE,SRC) TYPE##_real *VAR = (TYPE##_real *)SRC

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
    extern GHashTable *session_hash;
    extern GHashTable *key_hash;
    extern GRWLock rwlock;
}

namespace keyagent {
    namespace localcache {
        extern gpointer connection_pointer;
        extern gboolean cache_sessions;
        extern gboolean cache_keys;
        extern GRWLock cache_rwlock;
    }
}

#define GPOINTER_TO_GDA_CONNECTION(p) ((GdaConnection *)(p))

#endif

#define KEYAGENT_MODULE_LOOKUP(MODULE,FUNCNAME,RET, ERRCLASS) do { \
	if (!g_module_symbol ((MODULE), (FUNCNAME), (gpointer *)&(RET))) \
    { \
		g_set_error (&tmp_error, KEYAGENT_ERROR, (ERRCLASS), \
                   "%s: %s", filename, g_module_error ()); \
		goto errexit; \
    } \
} while (0)

#ifdef  __cplusplus
extern "C" {
#endif

void initialize_stm(gpointer data, gpointer user_data);
void initialize_npm(gpointer data, gpointer user_data);
gboolean keyagent_cache_init(GError **err);

void keyagent_session_hash_key_free(gpointer data);
void keyagent_session_hash_value_free(gpointer data);
void keyagent_key_hash_key_free(gpointer data);
void keyagent_key_hash_value_free(gpointer data);

gboolean keyagent_cache_loadsessions(GError **error);
gboolean keyagent_cache_session(keyagent_session *session, GError **error);
const char *keyagent_session_get_stmname(keyagent_session *session, GError **error);
const char *keyagent_key_get_stmname(keyagent_key *key, GError **error);

gboolean keyagent_cache_loadkeys(GError **error);
gboolean keyagent_cache_key(keyagent_key *key, GError **error);
gboolean keyagent_uncache_key(keyagent_key *key, GError **error);

void keyagent_session_set_cache_id(keyagent_session *, gint id);
gint keyagent_session_get_cache_id(keyagent_session *d);
void keyagent_key_set_cache_id(keyagent_key *, gint id);
gint keyagent_key_get_cache_id(keyagent_key *);
gint keyagent_key_get_session_cache_id(keyagent_key *);
//keyagent_session *keyagent_session_id_lookup(gint id);
gint keyagent_cache_generate_fake_id();
void keyagent_key_remove_by_session(keyagent_session *);

#ifdef  __cplusplus
}
#endif

#endif
