#ifndef _KEYAGENT_TYPES_
#define _KEYAGENT_TYPES_

#include "k_types.h"
#include "k_errors.h"

#define NONCE_LENGTH	32
typedef struct {
	GString *label;
}keyagent_module;

#define keyagent_get_module_label(MODULE) ((keyagent_module *)(MODULE))->label->str

#define keyagent_set_module_label(MODULE,LABEL) do { \
	((keyagent_module *)(MODULE))->label = g_string_new((LABEL)); \
}while(0)

typedef gchar * keyagent_url;

typedef enum {
	KEYAGENT_RSAKEY = 1,
	KEYAGENT_AESKEY,
	KEYAGENT_INVALIDKEY,
}keyagent_keytype;

typedef enum {
	KEYAGENT_KEY_FORMAT_PEM = 1,
	KEYAGENT_KEY_FORMAT_PKCS11,
}keyagent_keyserver_key_format;

typedef struct {
	k_buffer_ptr swk;
	GString *name;
	GString *session_id;
	GString *swk_type;
}keyagent_session;

typedef struct {
	GString  *url;
	keyagent_keytype type;
}keyagent_key;

typedef struct {
	unsigned int iv_length;
	unsigned int tag_size;
	unsigned int wrap_size;
}keyagent_keytransfer_t;

#define KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(ATTRS, src) do { \
	if((src)) { \
		const gchar *keyname = g_quark_to_string(KEYAGENT_ATTR_##src); \
		g_hash_table_insert((ATTRS)->hash, (gpointer) keyname, (gpointer)k_buffer_ref((src))); \
	} \
}while(0)

#define KEYAGENT_KEY_GET_BYTEARRAY_ATTR(ATTRS, NAME, DEST) do { \
	const gchar *keyname = g_quark_to_string(KEYAGENT_ATTR_##NAME); \
	DEST = (k_buffer_ptr)g_hash_table_lookup((ATTRS)->hash, keyname); \
}while(0)

#define KEYAGENT_DEFINE_QUARK(TYPE,QN)                                  \
extern "C" GQuark                                                       \
keyagent_##TYPE##_##QN##_quark(void)                                   \
{                                                                       \
	static GQuark q;                                                \
	if G_UNLIKELY (q == 0)                                          \
		q = g_quark_from_static_string("KEYAGENT_"#TYPE"_"#QN);\
	return q;                                                       \
}

#define KEYAGENT_QUARK(TYPE,NAME) keyagent_##TYPE##_##NAME##_quark()
#define KEYAGENT_DECLARE_ATTR(NAME) (KEYAGENT_QUARK(ATTR,NAME))
#define KEYAGENT_DECLARE_SWKTYPE(NAME) (KEYAGENT_QUARK(SWKTYPE,NAME))

static inline GQuark
keyagent_quark_to_string(const char *type, const char *name)
{
	GString *tmp = g_string_new("KEYAGENT");
	if(type)
		g_string_append_printf(tmp, "_%s", type);
	if(name)
		g_string_append_printf(tmp, "_%s", name);
	GQuark q = g_quark_from_string(tmp->str);
	g_string_free(tmp, TRUE);
	return q;
}

#define KEYAGENT_DEFINE_SWK_TYPES() \
	KEYAGENT_DEFINE_QUARK(SWKTYPE,AES128_GCM) \
	KEYAGENT_DEFINE_QUARK(SWKTYPE,AES192_GCM) \
	KEYAGENT_DEFINE_QUARK(SWKTYPE,AES256_GCM) \
	KEYAGENT_DEFINE_QUARK(SWKTYPE,AES128_WRAP) \
	KEYAGENT_DEFINE_QUARK(SWKTYPE,AES192_WRAP) \
	KEYAGENT_DEFINE_QUARK(SWKTYPE,AES256_WRAP)

#define KEYAGENT_DEFINE_KEY_ATTRIBUTES()	KEYAGENT_DEFINE_QUARK(ATTR,KEYDATA)

#define KEYAGENT_DEFINE_ATTRIBUTES() \
	KEYAGENT_DEFINE_SWK_TYPES() \
	KEYAGENT_DEFINE_KEY_ATTRIBUTES() \
	KEYAGENT_DEFINE_QUARK(ATTR,SWK) \
	KEYAGENT_DEFINE_QUARK(ATTR,CHALLENGE_KEYTYPE) \
	KEYAGENT_DEFINE_QUARK(ATTR,CHALLENGE_RSA_PUBLIC_KEY) \
	KEYAGENT_DEFINE_QUARK(ATTR,SW_ISSUER)

#define KEYAGENT_ATTR_KEYDATA			KEYAGENT_DECLARE_ATTR(KEYDATA)
#define KEYAGENT_ATTR_SWK			KEYAGENT_DECLARE_ATTR(SWK)
#define KEYAGENT_ATTR_CHALLENGE_KEYTYPE		KEYAGENT_DECLARE_ATTR(CHALLENGE_KEYTYPE)
#define KEYAGENT_ATTR_CHALLENGE_RSA_PUBLIC_KEY	KEYAGENT_DECLARE_ATTR(CHALLENGE_RSA_PUBLIC_KEY)
#define KEYAGENT_ATTR_SW_ISSUER			KEYAGENT_DECLARE_ATTR(SW_ISSUER)

#ifdef  __cplusplus
extern "C" {
#endif

GQuark KEYAGENT_ATTR_KEYDATA;
GQuark KEYAGENT_ATTR_SWK;
GQuark KEYAGENT_ATTR_CHALLENGE_KEYTYPE;
GQuark KEYAGENT_ATTR_CHALLENGE_RSA_PUBLIC_KEY;
GQuark KEYAGENT_ATTR_SW_ISSUER;

#ifdef  __cplusplus
}
#endif

#ifdef  __cplusplus
#define SKC_EXTERN extern "C"
#else
#define SKC_EXTERN extern
#endif

#define DECLARE_KEYAGENT_INTERFACE(SUBTYPE, NAME, RETURNTYPE, ARGS) \
    typedef RETURNTYPE (* SUBTYPE##_##NAME##_func) ARGS; \
    SKC_EXTERN RETURNTYPE SUBTYPE##_##NAME ARGS

#define DECLARE_KEYAGENT_OP(SUBTYPE,NAME) \
    SUBTYPE##_##NAME##_func SUBTYPE##_func_##NAME

#define INIT_KEYAGENT_INTERFACE(SUBTYPE,MODULE,NAME,ERROR) \
    KEYAGENT_MODULE_LOOKUP((MODULE)->module, #SUBTYPE"_"#NAME, (MODULE)->ops.SUBTYPE##_func_##NAME, (ERROR))

#define KEYAGENT_MODULE_LOOKUP(MODULE,FUNCNAME,RET, ERRCLASS) do { \
	if(!g_module_symbol((MODULE), (FUNCNAME), (gpointer *)&(RET))) \
	{ \
		g_set_error(&tmp_error, KEYAGENT_ERROR, (ERRCLASS), \
			"%s", g_module_error ()); \
		goto errexit; \
	} \
}while(0)

#define KEYAGENT_MODULE_OP(SUBTYPE,MODULE,NAME)  (MODULE)->ops.SUBTYPE##_func_##NAME

typedef enum {
	KEYAGENT_ERROR = 1,
	STM_ERROR,
	APIMODULE_ERROR,
}ErrorClass;

typedef enum {
	KEYAGENT_ERROR_NPMLOAD = 1,
	KEYAGENT_ERROR_KEYINIT,
	KEYAGENT_ERROR_STMLOAD,
	KEYAGENT_ERROR_KEY_CREATE_PARAMS,
	KEYAGENT_ERROR_NPM_URL_UNSUPPORTED,
	KEYAGENT_ERROR_KEY_CREATE_INVALID_SESSION_ID,
	KEYAGENT_ERROR_SESSION_CREATE_INVALID_LABEL,
	KEYAGENT_ERROR_SESSION_CREATE_INVALID_SWK_TYPE,
	KEYAGENT_ERROR_INVALID_KEYFORMAT,
	KEYAGENT_ERROR_INVALID_CONF_VALUE,
	KEYAGENT_ERROR_OUT_OF_MEMORY,
	KEYAGENT_ERROR_INVALID_CERT_INFO,
	APIMODULE_ERROR_INVALID_CONF_VALUE,
	APIMODULE_ERROR_INVALID_INPUT,
	APIMODULE_ERROR_API_RETURN_ERROR,
}KeyAgentErrors;

typedef enum {
	STM_ERROR_QUOTE = 1,
	STM_ERROR_API_MODULE_LOADKEY,
	STM_ERROR_INVALID_CHALLENGE_DATA,
	STM_ERROR_INVALID_LOADKEY_DATA,
	STM_ERROR_INVALID_SESSION_DATA,
}StmErrors;

typedef enum {
	NPM_ERROR_INIT = 1,
	NPM_ERROR_REGISTER,
	NPM_ERROR_KEYSERVER_ERROR,
	NPM_ERROR_LOAD_KEY,
	NPM_ERROR_JSON_PARSE,
	NPM_ERROR_INVALID_STATUS,
	NPM_ERROR_INVALID_SESSION_DATA,
}NpmErrors;

#define DECLARE_KEYAGENT_INTERNAL_OP(SUBTYPE, NAME, RETURNTYPE, ARGS) \
	typedef RETURNTYPE (* SUBTYPE##_##NAME##_func) ARGS; \
	SKC_EXTERN RETURNTYPE __##SUBTYPE##_##NAME ARGS

DECLARE_KEYAGENT_INTERNAL_OP(keyagent,stm_set_session, gboolean,(const char *request_id, keyagent_session *, GError **));
DECLARE_KEYAGENT_INTERNAL_OP(keyagent,stm_get_challenge, gboolean, (const char *request_id, unsigned char *nonce, const char *name, k_buffer_ptr *challenge, GError **));
DECLARE_KEYAGENT_INTERNAL_OP(keyagent,session_get_ids,GString *,());
DECLARE_KEYAGENT_INTERNAL_OP(keyagent,session_create, gboolean, (const char *request_id, const char *name, const char *session_id, k_buffer_ptr swk, const char *swk_type, GError **));
DECLARE_KEYAGENT_INTERNAL_OP(keyagent,session_lookup_swktype, GQuark, (const char *type));
DECLARE_KEYAGENT_INTERNAL_OP(keyagent,key_create, GQuark,(const char *request_id, keyagent_url url, keyagent_keytype type, k_attributes_ptr attrs, const char *session_id, GError **error));

typedef struct {
	DECLARE_KEYAGENT_OP(keyagent,stm_set_session);
	DECLARE_KEYAGENT_OP(keyagent,stm_get_challenge);
	DECLARE_KEYAGENT_OP(keyagent,session_get_ids);
	DECLARE_KEYAGENT_OP(keyagent,session_create);
	DECLARE_KEYAGENT_OP(keyagent,session_lookup_swktype);
	DECLARE_KEYAGENT_OP(keyagent,key_create);
}keyagent_npm_callbacks;

#define KEYAGENT_NPM_OP(OPS,NAME)  (OPS)->keyagent_func_##NAME

typedef struct {
	const char *request_id;
	keyagent_url url;
	GString *stm_names;
	keyagent_ssl_opts ssl_opts;
	keyagent_npm_callbacks cbs;
}keyagent_keyload_details;

typedef struct {
	const char *label;
	keyagent_url url;
	keyagent_keytype type;
	k_buffer_ptr key;
	k_buffer_ptr iv;
	unsigned long tag_size;
	void *module_data;
}keyagent_apimodule_loadkey_details;

typedef gboolean (*apimodule_load_key_func)(keyagent_apimodule_loadkey_details *, void *, GError **);

typedef struct {
	const char *label;
	void *module_data;
	GQuark swk_type;
	int swk_size_in_bits;
	k_buffer_ptr session;
}keyagent_apimodule_session_details;

struct ka_apimodule_ops;
typedef gboolean (*apimodule_set_wrapping_key_func)(keyagent_apimodule_session_details *, void *,GError **);
typedef gboolean (*apimodule_initialize_func)(struct ka_apimodule_ops *ops, GError **);
typedef gboolean (*apimodule_load_uri_func)(const char *uri);

typedef struct {
	const char *label;
	unsigned char nonce[NONCE_LENGTH];
	k_buffer_ptr challenge;
	void *module_data;
}keyagent_apimodule_get_challenge_details;

typedef gboolean (*apimodule_get_challenge_func)(keyagent_apimodule_get_challenge_details *, void *, GError **);

typedef struct {
	const char *request_id;
	GQuark swk_quark;
	apimodule_load_key_func apimodule_load_key_cb;
	keyagent_apimodule_loadkey_details apimodule_details;
}keyagent_stm_loadkey_details;

typedef struct {
	const char *request_id;
	apimodule_set_wrapping_key_func set_wrapping_key_cb;
	keyagent_apimodule_session_details apimodule_details;
}keyagent_stm_session_details;

typedef struct {
	const char *request_id;
	apimodule_get_challenge_func apimodule_get_challenge_cb;
	keyagent_apimodule_get_challenge_details apimodule_details;
}keyagent_stm_create_challenge_details;

typedef struct ka_apimodule_ops {
	apimodule_initialize_func init;
	apimodule_load_uri_func load_uri;
	apimodule_load_key_func load_key;
	apimodule_get_challenge_func get_challenge;
	apimodule_set_wrapping_key_func set_wrapping_key;
}keyagent_apimodule_ops;

typedef struct ecdsa_quote_verify_data
{
	u_int32_t  quote_size;
}ecdsa_quote_verify_data;

typedef struct sw_quote_verify_data{
	u_int32_t dummy;
}sw_quote_verify_data;

typedef union qdetails {
	ecdsa_quote_verify_data ecdsa_quote_details;
	sw_quote_verify_data sw_quto_details;	
}apimodule_quote_details;

struct keyagent_sgx_quote_info {
	struct {
		u_int32_t exponent_len;
		u_int32_t modulus_len;
	}rsa;
	apimodule_quote_details quote_details;
};

struct keyagent_sgx_challenge_request {
	gint launch_policy;
	unsigned char nonce[NONCE_LENGTH];
	const char *attestationType;
};
#endif
