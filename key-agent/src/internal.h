#ifndef __KEYAGENT_INTERNAL__
#define __KEYAGENT_INTERNAL__

#include <gmodule.h>
#include "key-agent/types.h"
#include "key-agent/npm/npm.h"
#include "key-agent/stm/stm.h"

typedef struct {
	keyagent_module npm;
	GString *module_name;
	GModule *module;
	guint initialized:1;
	GQueue *key_queue;
	npm_ops ops;
}keyagent_npm_real;

typedef struct {
	gint id;
	guint cached:1;
}keyagent_cache_state;

typedef struct {
	k_buffer_ptr swk;
	GString *name;
	GString *session_id;
	GString *swk_type;
	keyagent_cache_state cache_state;
}keyagent_session_real;

typedef struct {
	keyagent_module stm;
	GString *module_name;
	GModule *module;
	guint initialized:1;
	stm_ops ops;
	keyagent_session_real *session;
	gboolean apimodule;
}keyagent_stm_real;

typedef struct {
	GString *url;
	keyagent_keytype type;
	keyagent_session *session;
	k_attributes_ptr attributes;
	k_attributes_ptr policy_attributes;
	keyagent_cache_state cache_state;
}keyagent_key_real;

#define DECLARE_KEYAGENT_REAL_PTR(VAR,TYPE,SRC) TYPE##_real *VAR = (TYPE##_real *)SRC

#define ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,SUBTYPE, NAME) \
	(OPS)->SUBTYPE##_func_##NAME = __##SUBTYPE##_##NAME

#define LOOKUP_KEYAGENT_INTERNAL_NPM_OPS(OPS) do { \
	ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,stm_set_session); \
	ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,stm_get_challenge); \
	ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,session_get_ids); \
	ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,session_create); \
	ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,session_lookup_swktype); \
	ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,key_create); \
	ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,key_policy_add); \
}while(0)

#ifdef  __cplusplus

namespace keyagent {
	extern GString *configdirectory;
	extern GString *configfilename;
	extern void *config;
	extern GString *npm_directory;
	extern GString *stm_directory;
	extern keyagent_keyserver_key_format keyformat;
	extern gboolean ssl_verify;
	extern GString *cert;
	extern GString *certkey;
	extern GString *cacert;
	extern GHashTable *npm_hash;
	extern GHashTable *stm_hash;
	extern GHashTable *session_hash;
	extern GHashTable *key_hash;
	extern GHashTable *swk_type_hash;
	extern GHashTable *apimodule_loadkey_hash;
	extern GRWLock rwlock;
	extern keyagent_npm_callbacks npm_ops;
	extern keyagent_apimodule_ops apimodule_ops;
	extern gboolean apimodule_enabled;
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

typedef struct _request {
	void *module_data;
	GString *npm_name;
	GString *stm_name;
}keyagent_request;

#define CERTIFICATE_FILE_FORMAT "PEM"
#define KEYAGENT_KEY_FORMAT_PEM_STR "PEMFILE"
#define KEYAGENT_KEY_FORMAT_PKCS11_STR "PKCS11"
#define CERTIFICATE_FILE_FORMAT "PEM"

#ifdef  __cplusplus
extern "C" {
#endif

void __initialize_stm(gpointer data, gpointer user_data);
void __initialize_npm(gpointer data, gpointer user_data);

gboolean __keyagent_cache_init(GError **err);
void __keyagent_session_hash_key_free(gpointer data);
void __keyagent_session_hash_value_free(gpointer data);
void __keyagent_key_hash_key_free(gpointer data);
void __keyagent_key_hash_value_free(gpointer data);
gboolean __keyagent_cache_loadsessions(GError **error);
gboolean __keyagent_cache_session(keyagent_session *session, GError **error);
const char *__keyagent_session_get_stmname(keyagent_session *session, GError **error);
const char *__keyagent_key_get_stmname(keyagent_key *key, GError **error);
keyagent_key * __keyagent_key_lookup(const char *url);
gboolean __keyagent_key_free(keyagent_key *);
gboolean __keyagent_stm_load_key(const char *request_id, keyagent_key *key, GError **error);
GQuark __keyagent_key_create(const char *request_id, keyagent_url url, keyagent_keytype type, k_attributes_ptr attrs,
    const char *session_id, GError **error);
GQuark __keyagent_key_create_with_cacheid(const char *request_id, keyagent_url url, keyagent_keytype type, k_attributes_ptr attrs, 
    const char *session_id, gint cache_id, GError **error);
gboolean __keyagent_cache_loadkeys(GError **error);
gboolean __keyagent_cache_key(keyagent_key *key, GError **error);
gboolean __keyagent_uncache_key(keyagent_key *key, GError **error);
gboolean __keyagent_cache_loadkeys_policy_attr(GError **error);
gboolean __keyagent_cache_key_policy(keyagent_key *_key, GError **error);
void __keyagent_session_set_cache_id(keyagent_session *, gint id);
gint __keyagent_session_get_cache_id(keyagent_session *d);
void __keyagent_key_set_cache_id(keyagent_key *, gint id);
gint __keyagent_key_get_cache_id(keyagent_key *);
gint __keyagent_key_get_session_cache_id(keyagent_key *);
gint __keyagent_cache_generate_fake_id();
void __keyagent_key_remove_by_session(keyagent_session *);
GQuark __keyagent_session_make_swktype(const char *type);
gboolean __keyagent_session_init(GError **error);
gboolean __keyagent_stm_apimodule_enable(const char *name);
GString *__keyagent_stm_get_names();
GString *__keyagent_stm_get_apimodule_enabled_names();
gboolean __keyagent_stm_get_by_name(const char *name, keyagent_module **);
GString * __keyagent_session_get_ids();
keyagent_session * __keyagent_session_lookup(const char *session_id);
gboolean keyagent_session_create(const char *request_id, const char *name, const char *session_id, k_buffer_ptr swk, const char *swk_type, gint cache_id, GError **);
gboolean __keyagent_session_create(const char *request_id, const char *name, const char *session_id, k_buffer_ptr swk, const char *swk_type, GError **);
gboolean __keyagent_stm_set_session(const char *request_id, keyagent_session *, GError **);
GQuark __keyagent_session_lookup_swktype(const char *type);
gboolean  __keyagent_stm_get_challenge(const char *name, const char *requesting_npm_name, k_buffer_ptr *challenge, GError **);
const char *keyagent_generate_request_id(void);
void keyagent_request_id_destory(gpointer data);

#ifdef  __cplusplus
}
#endif

#endif
