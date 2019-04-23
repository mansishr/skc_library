#ifndef _KEYAGENT_TYPES_
#define _KEYAGENT_TYPES_

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include "k_types.h"
#include "k_errors.h"
#include "k_debug.h"

typedef struct {
    GString *label;
} keyagent_module;

#define keyagent_get_module_label(MODULE) ((keyagent_module *)(MODULE))->label->str

#define keyagent_set_module_label(MODULE,LABEL) do { \
	((keyagent_module *)(MODULE))->label = g_string_new((LABEL)); \
} while(0)

typedef gchar * keyagent_url;


typedef enum {
    KEYAGENT_RSAKEY = 1,
    KEYAGENT_ECKEY,
    KEYAGENT_AESKEY,
} keyagent_keytype;

typedef enum {
    KEYAGENT_KEY_FORMAT_PEM = 1,
    KEYAGENT_KEY_FORMAT_PKCS11,
} keyagent_keyserver_key_format;

typedef enum {
    KEYAGENT_AES_MODE_CTR,
    KEYAGENT_AES_MODE_GCM,
    KEYAGENT_AES_MODE_CBC,
    KEYAGENT_AES_MODE_XTS,
    KEYAGENT_AES_MODE_EBC,
    KEYAGENT_AES_MODE_WRAP,
} keyagent_aes_mode;

typedef struct {
    k_buffer_ptr		swk;
    GString                 *name;
    GString                 *session_id;
    GString                 *swk_type;
} keyagent_session;

typedef struct {
	const char *certfile;
	const char *ca_certfile;
	const char *certtype;
	const char *keyname;
	const char *keytype;
    gboolean ssl_verify;
} keyagent_ssl_opts;


typedef struct {
    GString  *url;
    keyagent_keytype type;
} keyagent_key;

typedef struct {
    unsigned int  iv_length;
    unsigned int  tag_size;
    unsigned int  wrap_size;
} keyagent_keytransfer_t;

#define KEYAGENT_KEY_ADD_POLICY_ATTR(ATTRS, policy) do { \
	if ((policy)) { \
        const gchar *policyname = g_quark_to_string ( KEYAGENT_ATTR_POLICY_##policy ); \
	    g_hash_table_insert((ATTRS)->hash, (gpointer) policyname,  (gpointer) k_policy_buffer_ref((policy))); \
	} \
} while(0)

#define KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(ATTRS, src) do { \
	if ((src)) { \
        const gchar *keyname = g_quark_to_string ( KEYAGENT_ATTR_##src ); \
	    g_hash_table_insert((ATTRS)->hash, (gpointer) keyname,  (gpointer) k_buffer_ref((src))); \
	} \
} while(0)

#define KEYAGENT_KEY_REPLACE_BYTEARRAY_ATTR(ATTRS, src) do { \
	if ((src)) { \
        const gchar *keyname = g_quark_to_string ( KEYAGENT_ATTR_##src ); \
	    g_hash_table_replace((ATTRS)->hash, (gpointer) keyname,  (gpointer) k_buffer_ref((src))); \
	} \
} while(0)

#define KEYAGENT_KEY_GET_POLICY_ATTR(ATTRS, NAME, DEST) do { \
    const gchar *keyname = g_quark_to_string ( KEYAGENT_ATTR_POLICY_##NAME ); \
    DEST = (k_policy_buffer_ptr)g_hash_table_lookup((ATTRS)->hash, keyname); \
} while(0)


#define KEYAGENT_KEY_GET_BYTEARRAY_ATTR(ATTRS, NAME, DEST) do { \
    const gchar *keyname = g_quark_to_string ( KEYAGENT_ATTR_##NAME ); \
    DEST = (k_buffer_ptr)g_hash_table_lookup((ATTRS)->hash, keyname); \
} while(0)

#define ENCRYPT_ATTR_HASH(VAL, SRC_ATTR, DEST_ATTRS, KEY, IV, ENCRYPT_FUNC) do { \
    k_buffer_ptr tmp; \
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(SRC_ATTR, VAL, tmp); \
    k_buffer_ptr VAL = k_buffer_alloc(NULL, k_buffer_length(tmp) + TAG_SIZE); \
	k_debug_generate_checksum("BEFORE-E-"#VAL, k_buffer_data(tmp), k_buffer_length(tmp)); \
    ENCRYPT_FUNC(tmp, KEY, IV, VAL); \
    k_debug_generate_checksum("AFTER-E-"#VAL, k_buffer_data(VAL), k_buffer_length(VAL)); \
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(DEST_ATTRS, VAL); \
    k_buffer_unref(VAL); \
} while(0)

#define DECRYPT_ATTR_HASH(VAL, SRC_ATTR, DEST_ATTRS, KEY, IV, TAGLEN, DECRYPT_FUNC) do { \
    k_buffer_ptr tmp; \
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(SRC_ATTR, VAL, tmp); \
    k_buffer_ptr VAL = k_buffer_alloc(NULL, k_buffer_length(tmp) - TAGLEN); \
    k_debug_generate_checksum("BEFORE-D-"#VAL, k_buffer_data(tmp), k_buffer_length(tmp)); \
    DECRYPT_FUNC(VAL, KEY, IV, tmp, TAGLEN); \
    k_debug_generate_checksum("AFTER-D-"#VAL, k_buffer_data(VAL), k_buffer_length(VAL)); \
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(DEST_ATTRS, VAL); \
    k_buffer_unref(VAL); \
} while(0)


#define COPY_ATTR_HASH(VAL, SRC_ATTR, DEST_ATTRS) do { \
    k_buffer_ptr VAL; \
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(SRC_ATTR, VAL, VAL); \
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(DEST_ATTRS, VAL); \
} while(0)



#define KEYAGENT_DEFINE_QUARK(TYPE,QN)                                         \
extern "C" GQuark                                                                  \
keyagent_##TYPE##_##QN##_quark (void)                                                  \
{                                                                       \
  static GQuark q;                                                      \
                                                                        \
  if G_UNLIKELY (q == 0)                                                \
    q = g_quark_from_static_string ("KEYAGENT_"#TYPE"_"#QN);                               \
                                                                        \
  return q;                                                             \
}

#define KEYAGENT_QUARK(TYPE,NAME)	keyagent_##TYPE##_##NAME##_quark()
#define KEYAGENT_DECLARE_ATTR(NAME) (KEYAGENT_QUARK(ATTR,NAME))
#define KEYAGENT_DECLARE_SWKTYPE(NAME) (KEYAGENT_QUARK(SWKTYPE,NAME))
#define KEYAGENT_DECLARE_ATTR_POLICY(NAME) (KEYAGENT_QUARK(ATTR_POLICY, NAME))

static inline GQuark
keyagent_quark_to_string(const char *type, const char *name)
{
	GString *tmp = g_string_new("KEYAGENT");
    if (type)
	    g_string_append_printf(tmp, "_%s", type);
    if (name)
	    g_string_append_printf(tmp, "_%s", name);
	GQuark q = g_quark_from_string(tmp->str);
	g_string_free(tmp, TRUE);
	return q;
}

#define KEYAGENT_DEFINE_SWK_TYPES() \
		KEYAGENT_DEFINE_QUARK(SWKTYPE,AES192_CTR) \
		KEYAGENT_DEFINE_QUARK(SWKTYPE,AES256_CTR) \
		KEYAGENT_DEFINE_QUARK(SWKTYPE,AES128_GCM) \
		KEYAGENT_DEFINE_QUARK(SWKTYPE,AES192_GCM) \
		KEYAGENT_DEFINE_QUARK(SWKTYPE,AES256_GCM) \
		KEYAGENT_DEFINE_QUARK(SWKTYPE,AES128_WRAP) \
		KEYAGENT_DEFINE_QUARK(SWKTYPE,AES192_WRAP) \
		KEYAGENT_DEFINE_QUARK(SWKTYPE,AES256_WRAP) \
		KEYAGENT_DEFINE_QUARK(SWKTYPE,AES128_CBC) \
		KEYAGENT_DEFINE_QUARK(SWKTYPE,AES192_CBC) \
		KEYAGENT_DEFINE_QUARK(SWKTYPE,AES256_CBC) \
		KEYAGENT_DEFINE_QUARK(SWKTYPE,AES128_XTS) \
		KEYAGENT_DEFINE_QUARK(SWKTYPE,AES256_XTS) 

#define KEYAGENT_DEFINE_KEY_ATTRIBUTES() \
    	KEYAGENT_DEFINE_QUARK(ATTR,KEYDATA)

#define KEYAGENT_DEFINE_POLITY_ATTRIBUTES() \
		KEYAGENT_DEFINE_QUARK(ATTR_POLICY, NOT_AFTER) \
		KEYAGENT_DEFINE_QUARK(ATTR_POLICY, NOT_BEFORE) \
		KEYAGENT_DEFINE_QUARK(ATTR_POLICY, CREATED_AT) 

#define KEYAGENT_DEFINE_ATTRIBUTES() \
        KEYAGENT_DEFINE_SWK_TYPES() \
		KEYAGENT_DEFINE_POLITY_ATTRIBUTES() \
        KEYAGENT_DEFINE_KEY_ATTRIBUTES() \
        KEYAGENT_DEFINE_QUARK(ATTR,STM_TEST_DATA) \
        KEYAGENT_DEFINE_QUARK(ATTR,STM_TEST_SIG) \
    	KEYAGENT_DEFINE_QUARK(ATTR,SWK) \
    	KEYAGENT_DEFINE_QUARK(ATTR,CHALLENGE_KEYTYPE) \
    	KEYAGENT_DEFINE_QUARK(ATTR,CHALLENGE_ECC_PUBLIC_KEY) \
    	KEYAGENT_DEFINE_QUARK(ATTR,CHALLENGE_RSA_PUBLIC_KEY) \
    	KEYAGENT_DEFINE_QUARK(ATTR,SW_ISSUER) \
    	KEYAGENT_DEFINE_QUARK(ATTR,SGX_ENCLAVE_ISSUER) \
    	KEYAGENT_DEFINE_QUARK(ATTR,SGX_ENCLAVE_ISSUER_PRODUCT_ID) \
    	KEYAGENT_DEFINE_QUARK(ATTR,SGX_ENCLAVE_ISSUER_EXTENDED_PRODUCT_ID) \
    	KEYAGENT_DEFINE_QUARK(ATTR,SGX_ENCLAVE_MEASUREMENT) \
    	KEYAGENT_DEFINE_QUARK(ATTR,SGX_ENCLAVE_SVN_MINIMUM_SGX_CONFIG_ID) \
    	KEYAGENT_DEFINE_QUARK(ATTR,SGX_CONFIG_ID_SVN) \
    	KEYAGENT_DEFINE_QUARK(ATTR,KPT_ISSUER)


#define KEYAGENT_ATTR_KEYDATA									KEYAGENT_DECLARE_ATTR(KEYDATA)
#define KEYAGENT_ATTR_STM_TEST_DATA								KEYAGENT_DECLARE_ATTR(STM_TEST_DATA)
#define KEYAGENT_ATTR_STM_TEST_SIG								KEYAGENT_DECLARE_ATTR(STM_TEST_SIG)
#define KEYAGENT_ATTR_SWK	                                    KEYAGENT_DECLARE_ATTR(SWK)
#define KEYAGENT_ATTR_CHALLENGE_KEYTYPE	                        KEYAGENT_DECLARE_ATTR(CHALLENGE_KEYTYPE)
#define KEYAGENT_ATTR_CHALLENGE_ECC_PUBLIC_KEY	                KEYAGENT_DECLARE_ATTR(CHALLENGE_ECC_PUBLIC_KEY)
#define KEYAGENT_ATTR_CHALLENGE_RSA_PUBLIC_KEY	                KEYAGENT_DECLARE_ATTR(CHALLENGE_RSA_PUBLIC_KEY)
#define KEYAGENT_ATTR_SW_ISSUER	                                KEYAGENT_DECLARE_ATTR(SW_ISSUER)
#define KEYAGENT_ATTR_SGX_ENCLAVE_ISSUER	                    KEYAGENT_DECLARE_ATTR(SGX_ENCLAVE_ISSUER)
#define KEYAGENT_ATTR_SGX_ENCLAVE_ISSUER_PRODUCT_ID	            KEYAGENT_DECLARE_ATTR(SGX_ENCLAVE_ISSUER_PRODUCT_ID)
#define KEYAGENT_ATTR_SGX_ENCLAVE_ISSUER_EXTENDED_PRODUCT_ID	KEYAGENT_DECLARE_ATTR(SGX_ENCLAVE_ISSUER_EXTENDED_PRODUCT_ID)
#define KEYAGENT_ATTR_SGX_ENCLAVE_MEASUREMENT	                KEYAGENT_DECLARE_ATTR(SGX_ENCLAVE_MEASUREMENT)
#define KEYAGENT_ATTR_SGX_ENCLAVE_SVN_MINIMUM_SGX_CONFIG_ID	    KEYAGENT_DECLARE_ATTR(SGX_ENCLAVE_SVN_MINIMUM_SGX_CONFIG_ID)
#define KEYAGENT_ATTR_SGX_CONFIG_ID_SVN	                        KEYAGENT_DECLARE_ATTR(SGX_CONFIG_ID_SVN)
#define KEYAGENT_ATTR_KPT_ISSUER	                            KEYAGENT_DECLARE_ATTR(KPT_ISSUER)


#define KEYAGENT_SWKTYPE_AES192_CTR								KEYAGENT_DECLARE_SWKTYPE(AES192_CTR)
#define KEYAGENT_SWKTYPE_AES256_CTR								KEYAGENT_DECLARE_SWKTYPE(AES256_CTR)
#define KEYAGENT_SWKTYPE_AES128_GCM								KEYAGENT_DECLARE_SWKTYPE(AES128_GCM)
#define KEYAGENT_SWKTYPE_AES192_GCM								KEYAGENT_DECLARE_SWKTYPE(AES192_GCM)
#define KEYAGENT_SWKTYPE_AES256_GCM								KEYAGENT_DECLARE_SWKTYPE(AES256_GCM)
#define KEYAGENT_SWKTYPE_AES128_WRAP								KEYAGENT_DECLARE_SWKTYPE(AES128_WRAP)
#define KEYAGENT_SWKTYPE_AES192_WRAP								KEYAGENT_DECLARE_SWKTYPE(AES192_WRAP)
#define KEYAGENT_SWKTYPE_AES256_WRAP								KEYAGENT_DECLARE_SWKTYPE(AES256_WRAP)
#define KEYAGENT_SWKTYPE_AES128_CBC								KEYAGENT_DECLARE_SWKTYPE(AES128_CBC)
#define KEYAGENT_SWKTYPE_AES192_CBC								KEYAGENT_DECLARE_SWKTYPE(AES192_CBC)
#define KEYAGENT_SWKTYPE_AES256_CBC								KEYAGENT_DECLARE_SWKTYPE(AES256_CBC)
#define KEYAGENT_SWKTYPE_AES128_XTS								KEYAGENT_DECLARE_SWKTYPE(AES128_XTS)
#define KEYAGENT_SWKTYPE_AES256_XTS								KEYAGENT_DECLARE_SWKTYPE(AES256_XTS)


#define KEYAGENT_ATTR_POLICY_NOT_AFTER                          KEYAGENT_DECLARE_ATTR_POLICY(NOT_AFTER)
#define KEYAGENT_ATTR_POLICY_NOT_BEFORE                         KEYAGENT_DECLARE_ATTR_POLICY(NOT_BEFORE)
#define KEYAGENT_ATTR_POLICY_CREATED_AT                         KEYAGENT_DECLARE_ATTR_POLICY(CREATED_AT)


#ifdef  __cplusplus
extern "C" {
#endif

GQuark KEYAGENT_ATTR_KEYDATA;
GQuark KEYAGENT_ATTR_STM_TEST_DATA;
GQuark KEYAGENT_ATTR_STM_TEST_SIG;
GQuark KEYAGENT_ATTR_SWK;
GQuark KEYAGENT_ATTR_CHALLENGE_KEYTYPE;
GQuark KEYAGENT_ATTR_CHALLENGE_ECC_PUBLIC_KEY;
GQuark KEYAGENT_ATTR_CHALLENGE_RSA_PUBLIC_KEY;
GQuark KEYAGENT_ATTR_SW_ISSUER;
GQuark KEYAGENT_ATTR_SGX_ENCLAVE_ISSUER;
GQuark KEYAGENT_ATTR_SGX_ENCLAVE_ISSUER_PRODUCT_ID;
GQuark KEYAGENT_ATTR_SGX_ENCLAVE_ISSUER_EXTENDED_PRODUCT_ID;
GQuark KEYAGENT_ATTR_SGX_ENCLAVE_MEASUREMENT;
GQuark KEYAGENT_ATTR_SGX_ENCLAVE_SVN_MINIMUM_SGX_CONFIG_ID;
GQuark KEYAGENT_ATTR_SGX_CONFIG_ID_SVN;
GQuark KEYAGENT_ATTR_KPT_ISSUER;

GQuark KEYAGENT_SWKTYPE_AES192_CTR;
GQuark KEYAGENT_SWKTYPE_AES256_CTR;
GQuark KEYAGENT_SWKTYPE_AES128_GCM;
GQuark KEYAGENT_SWKTYPE_AES192_GCM;
GQuark KEYAGENT_SWKTYPE_AES256_GCM;
GQuark KEYAGENT_SWKTYPE_AES128_WRAP;
GQuark KEYAGENT_SWKTYPE_AES192_WRAP;
GQuark KEYAGENT_SWKTYPE_AES256_WRAP;
GQuark KEYAGENT_SWKTYPE_AES128_CBC;
GQuark KEYAGENT_SWKTYPE_AES192_CBC;
GQuark KEYAGENT_SWKTYPE_AES256_CBC;
GQuark KEYAGENT_SWKTYPE_AES128_XTS;
GQuark KEYAGENT_SWKTYPE_AES256_XTS;

GQuark KEYAGENT_ATTR_POLICY_NOT_AFTER;
GQuark KEYAGENT_ATTR_POLICY_NOT_BEFORE;
GQuark KEYAGENT_ATTR_POLICY_CREATED_AT;

#ifdef  __cplusplus
}
#endif

#define TAG_SIZE    			16
#define AES_BLOCK_SIZE			16

#define EVP_CTRL_AEAD_SET_IVLEN 0x9
#define EVP_CTRL_AEAD_GET_TAG 	0x10
#define EVP_CTRL_AEAD_SET_TAG 	0x11
#define AES_128_KEY_SIZE 		16
#define AES_192_KEY_SIZE 		24
#define AES_256_KEY_SIZE 		32

#ifdef  __cplusplus
#define DHSM_EXTERN extern "C"
#else
#define DHSM_EXTERN extern
#endif

#define DECLARE_KEYAGENT_INTERFACE(SUBTYPE, NAME, RETURNTYPE, ARGS) \
    typedef RETURNTYPE (* SUBTYPE##_##NAME##_func) ARGS; \
    DHSM_EXTERN RETURNTYPE SUBTYPE##_##NAME ARGS

#define DECLARE_KEYAGENT_OP(SUBTYPE,NAME) \
    SUBTYPE##_##NAME##_func SUBTYPE##_func_##NAME

#define INIT_KEYAGENT_INTERFACE(SUBTYPE,MODULE,NAME,ERROR) \
    KEYAGENT_MODULE_LOOKUP((MODULE)->module, #SUBTYPE"_"#NAME, (MODULE)->ops.SUBTYPE##_func_##NAME, (ERROR))

#define KEYAGENT_MODULE_OP(SUBTYPE,MODULE,NAME)  (MODULE)->ops.SUBTYPE##_func_##NAME

typedef enum {
	KEYAGENT_ERROR = 1,
	STM_ERROR,
    APIMODULE_ERROR,
} ErrorClass;

typedef enum {
	KEYAGENT_ERROR_NPMLOAD = 1,
	KEYAGENT_ERROR_KEYINIT,
	KEYAGENT_ERROR_KEYCONF,
	KEYAGENT_ERROR_NPMKEYINIT,
	KEYAGENT_ERROR_STMLOAD,
	KEYAGENT_ERROR_KEY_CREATE_PARAMS,
    KEYAGENT_ERROR_BADCMS_MSG,
	KEYAGENT_ERROR_NPM_URL_UNSUPPORTED,
    KEYAGENT_ERROR_KEY_CREATE_INVALID_SESSION_ID,
    KEYAGENT_ERROR_SESSION_CREATE_INVALID_LABEL,
    KEYAGENT_ERROR_SESSION_CREATE_INVALID_SWK_TYPE,
    KEYAGENT_ERROR_INVALID_KEYFORMAT,
    KEYAGENT_ERROR_INVALID_CONF_VALUE,
    APIMODULE_ERROR_INVALID_FUNC_PTR,
    APIMODULE_ERROR_INVALID_CONF_VALUE,
} KeyAgentErrors;

typedef enum {
    STM_ERROR_QUOTE = 1,
	STM_ERROR_API_MODULE_LOADKEY,
	STM_ERROR_INVALID_CHALLENGE_DATA,
	STM_ERROR_INVALID_LOADKEY_DATA,
} StmErrors;

typedef enum {
	NPM_ERROR_INIT = 1,
    NPM_ERROR_REGISTER,
    NPM_ERROR_KEYSERVER_ERROR,
    NPM_ERROR_NOT_AUTHORIZED,
    NPM_ERROR_LOAD_KEY,
	NPM_ERROR_JSON_PARSE,
	NPM_ERROR_INVALID_STATUS,
	NPM_ERROR_INVALID_SESSION_DATA,
    NPM_ERROR_PARSE_JSON,
} NpmErrors;

#define DECLARE_KEYAGENT_INTERNAL_OP(SUBTYPE, NAME, RETURNTYPE, ARGS) \
    typedef RETURNTYPE (* SUBTYPE##_##NAME##_func) ARGS; \
    DHSM_EXTERN RETURNTYPE __##SUBTYPE##_##NAME ARGS

DECLARE_KEYAGENT_INTERNAL_OP(keyagent,stm_set_session, gboolean,(const char *request_id, keyagent_session *, GError **));
DECLARE_KEYAGENT_INTERNAL_OP(keyagent,stm_get_challenge, gboolean, (const char *request_id, const char *name, k_buffer_ptr *challenge, GError **));
DECLARE_KEYAGENT_INTERNAL_OP(keyagent,session_get_ids,GString *,());
DECLARE_KEYAGENT_INTERNAL_OP(keyagent,session_create, gboolean, (const char *request_id, const char *name, const char *session_id, k_buffer_ptr swk, const char *swk_type, GError **));
DECLARE_KEYAGENT_INTERNAL_OP(keyagent,session_lookup_swktype, GQuark, (const char *type));
DECLARE_KEYAGENT_INTERNAL_OP(keyagent,stm_challenge_verify, gboolean, (const char *name, k_buffer_ptr quote, k_attribute_set_ptr *challenge_attrs, GError **));

DECLARE_KEYAGENT_INTERNAL_OP(keyagent,https_send,int, (GString *url, GPtrArray *headers, GString *postdata, GPtrArray *response_headers, k_buffer_ptr returndata, keyagent_ssl_opts *ssl_opts, GString *userpwd, gboolean verbose));

DECLARE_KEYAGENT_INTERNAL_OP(keyagent,key_create, GQuark,(const char *request_id, keyagent_url url, keyagent_keytype type, k_attributes_ptr attrs, const char *session_id, GError **error));
DECLARE_KEYAGENT_INTERNAL_OP(keyagent,key_policy_add, gboolean, (keyagent_url url, k_attributes_ptr policy_attrs, gint cache_id, GError **error));

typedef struct {
    DECLARE_KEYAGENT_OP(keyagent,stm_set_session);
    DECLARE_KEYAGENT_OP(keyagent,stm_get_challenge);
    DECLARE_KEYAGENT_OP(keyagent,stm_challenge_verify);
    DECLARE_KEYAGENT_OP(keyagent,session_get_ids);
    DECLARE_KEYAGENT_OP(keyagent,session_create);
    DECLARE_KEYAGENT_OP(keyagent,session_lookup_swktype);
    DECLARE_KEYAGENT_OP(keyagent,https_send);
    DECLARE_KEYAGENT_OP(keyagent,key_create);
    DECLARE_KEYAGENT_OP(keyagent,key_policy_add);
} keyagent_npm_callbacks;

#define KEYAGENT_NPM_OP(OPS,NAME)  (OPS)->keyagent_func_##NAME

typedef struct {
    const char *request_id;
    keyagent_url url;
    GString *stm_names;
    keyagent_ssl_opts ssl_opts;
    keyagent_npm_callbacks cbs;
} keyagent_keyload_details;

typedef struct {
	const char *label;
    keyagent_url url;
    keyagent_keytype type;
    k_buffer_ptr key;
    k_buffer_ptr iv;
	int tag_size;
	void *module_data;
} keyagent_apimodule_loadkey_details;

typedef gboolean (*apimodule_load_key_func)(keyagent_apimodule_loadkey_details *, void *, GError **);

typedef struct {
	const char *label;
	void *module_data;
    GQuark swk_type;
    int swk_size_in_bits;
    k_buffer_ptr session;
} keyagent_apimodule_session_details;

typedef gboolean (*apimodule_set_wrapping_key_func)(keyagent_apimodule_session_details *, void *,GError **);

typedef struct {
	const char *label;
    k_buffer_ptr challenge;
	void *module_data;
} keyagent_apimodule_get_challenge_details;

typedef gboolean (*apimodule_get_challenge_func)(keyagent_apimodule_get_challenge_details *, void *, GError **);

typedef struct {
    const char *request_id;
    GQuark swk_quark;
	apimodule_load_key_func apimodule_load_key_cb;
	keyagent_apimodule_loadkey_details apimodule_details;
} keyagent_stm_loadkey_details;

typedef struct {
    const char *request_id;
	apimodule_set_wrapping_key_func set_wrapping_key_cb;
	keyagent_apimodule_session_details apimodule_details;
} keyagent_stm_session_details;

typedef struct {
    const char *request_id;
	apimodule_get_challenge_func apimodule_get_challenge_cb;
	keyagent_apimodule_get_challenge_details apimodule_details;
} keyagent_stm_create_challenge_details;

typedef struct {
	apimodule_load_key_func load_key;
	apimodule_get_challenge_func get_challenge;
	apimodule_set_wrapping_key_func set_wrapping_key;
} keyagent_apimodule_ops;

struct keyagent_sgx_quote_info {
    union {
        struct {
	        u_int32_t exponent_len;
	        u_int32_t modulus_len;
        } rsa;
        struct {
            u_int32_t dummy;
        } ec;
    } keydetails;
	keyagent_keytype keytype;
};

struct keyagent_sgx_challenge_request {
    gboolean linkable;
    const char *spid;
    const char *sigrl;
};

#endif
