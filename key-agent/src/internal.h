#ifndef __KEYAGENT_INTERNAL__
#define __KEYAGENT_INTERNAL__

#include <glib.h>
#include <errno.h>
#include "key-agent/types.h"
#include "key-agent/npm/npm.h"
#include "key-agent/stm/stm.h"
#include <gmodule.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>

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
    k_buffer_ptr		swk;
    GString                 *name;
    GString                 *session_id;
    GString                 *swk_type;
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
    k_attributes_ptr attributes;
    k_attributes_ptr policy_attributes;
    keyagent_cache_state	cache_state;
} keyagent_key_real;

#define DECLARE_KEYAGENT_REAL_PTR(VAR,TYPE,SRC) TYPE##_real *VAR = (TYPE##_real *)SRC


#define ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,SUBTYPE, NAME) \
    (OPS)->SUBTYPE##_func_##NAME = __##SUBTYPE##_##NAME

#define LOOKUP_KEYAGENT_INTERNAL_NPM_OPS(OPS) do { \
    ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,stm_set_session); \
    ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,stm_get_challenge); \
    ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,stm_challenge_verify); \
    ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,session_get_ids); \
    ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,session_create); \
    ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,session_lookup_swktype); \
    ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,https_send); \
    ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,key_create); \
    ASSIGN_KEYAGENT_INTERNAL_NPM_OP(OPS,keyagent,key_policy_add); \
} while(0)

#define ASSIGN_KEYAGENT_INTERNAL_STM_OP(OPS,SUBTYPE, NAME) \
    (OPS)->SUBTYPE##_func_##NAME = __##SUBTYPE##_##NAME

#define LOOKUP_KEYAGENT_INTERNAL_STM_OPS(OPS) do { \
    ASSIGN_KEYAGENT_INTERNAL_STM_OP(OPS,keyagent,get_swk_size); \
    ASSIGN_KEYAGENT_INTERNAL_STM_OP(OPS,keyagent,aes_decrypt); \
    ASSIGN_KEYAGENT_INTERNAL_STM_OP(OPS,keyagent,verify_and_extract_cms_message); \
} while(0)

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
    extern GHashTable *swk_type_hash;
    extern GRWLock rwlock;
    extern keyagent_npm_callbacks npm_ops;
    extern keyagent_stm_callbacks stm_ops;
    extern keyagent_apimodule_ops apimodule_ops;
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


typedef struct swk_op{
	int keybits;
	const EVP_CIPHER* (* cipher_func )(void);
	int (* encrypt_func)(k_buffer_ptr plaintext, void *swk_info, k_buffer_ptr iv, k_buffer_ptr ciphertext);
	k_buffer_ptr (* decrypt_func)(struct swk_op *swk_op, k_buffer_ptr msg, k_buffer_ptr key, int tlen, k_buffer_ptr iv);
} swk_type_op;


#define KEYAGENT_MODULE_LOOKUP(MODULE,FUNCNAME,RET, ERRCLASS) do { \
	if (!g_module_symbol ((MODULE), (FUNCNAME), (gpointer *)&(RET))) \
    { \
		g_set_error (&tmp_error, KEYAGENT_ERROR, (ERRCLASS), \
                   "%s", g_module_error ()); \
		goto errexit; \
    } \
} while (0)

#define CERTIFICATE_FILE_FORMAT "PEM"

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

keyagent_key * __keyagent_key_lookup(const char *url);
gboolean __keyagent_key_free(keyagent_key *);

gboolean __keyagent_stm_load_key(keyagent_key *key, GError **error);


GQuark __keyagent_key_create(keyagent_url url, keyagent_keytype type, k_attributes_ptr attrs,
    const char *session_id, GError **error);

GQuark __keyagent_key_create_with_cacheid(keyagent_url url, keyagent_keytype type, k_attributes_ptr attrs, 
    const char *session_id, gint cache_id, GError **error);

gboolean keyagent_cache_loadkeys(GError **error);
gboolean keyagent_cache_key(keyagent_key *key, GError **error);
gboolean keyagent_uncache_key(keyagent_key *key, GError **error);
gboolean keyagent_cache_loadkeys_policy_attr(GError **error);

gboolean keyagent_cache_key_policy(keyagent_key *_key, GError **error);

void keyagent_session_set_cache_id(keyagent_session *, gint id);
gint keyagent_session_get_cache_id(keyagent_session *d);
void keyagent_key_set_cache_id(keyagent_key *, gint id);
gint keyagent_key_get_cache_id(keyagent_key *);
gint keyagent_key_get_session_cache_id(keyagent_key *);
//keyagent_session *keyagent_session_id_lookup(gint id);
gint keyagent_cache_generate_fake_id();
void keyagent_key_remove_by_session(keyagent_session *);

GQuark keyagent_session_make_swktype(const char *type);
gboolean keyagent_session_init(GError **error);
k_buffer_ptr aes_gcm_decrypt(swk_type_op *sw_op, k_buffer_ptr msg, k_buffer_ptr key, int tlen, k_buffer_ptr iv);
k_buffer_ptr aes_cbc_decrypt(swk_type_op *sw_op, k_buffer_ptr msg, k_buffer_ptr key, int tlen, k_buffer_ptr iv);

GString *__keyagent_stm_get_names();
gboolean __keyagent_stm_get_by_name(const char *name, keyagent_module **);
GString * __keyagent_session_get_ids();
keyagent_session * __keyagent_session_lookup(const char *session_id);

gboolean __keyagent_session_create(const char *name, const char *session_id, k_buffer_ptr swk, const char *swk_type, gint cache_id, GError **);
gboolean __keyagent_stm_set_session(keyagent_session *, GError **);
GQuark __keyagent_session_lookup_swktype(const char *type);
gboolean  __keyagent_stm_get_challenge(const char *name, k_buffer_ptr *challenge, GError **);
gboolean __keyagent_stm_challenge_verify(const char *name, k_buffer_ptr quote, k_attributes_ptr *challenge_attrs, GError **);

#ifdef  __cplusplus
}
#endif

#endif
