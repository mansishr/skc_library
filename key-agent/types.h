#ifndef _KEYAGENT_TYPES_
#define _KEYAGENT_TYPES_

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include "k_errors.h"

typedef struct {
    GString *label;
} keyagent_module;

#define keyagent_get_module_label(MODULE) ((keyagent_module *)(MODULE))->label->str

#define keyagent_set_module_label(MODULE,LABEL) do { \
	((keyagent_module *)(MODULE))->label = g_string_new((LABEL)); \
} while(0)

typedef gchar * keyagent_url;

typedef struct {
	GByteArray *bytes;
    gint ref_count;
} keyagent_buffer;

typedef keyagent_buffer *	keyagent_buffer_ptr;

#define keyagent_buffer_data(PTR) (PTR)->bytes->data
#define keyagent_buffer_length(PTR) (PTR)->bytes->len

static inline void
keyagent_buffer_append(keyagent_buffer_ptr buf, void *data, int size)
{
	g_byte_array_append (buf->bytes, (guint8*) data, size);
}

static inline keyagent_buffer_ptr
keyagent_buffer_alloc(void *data, int size)
{
    keyagent_buffer_ptr buf = g_new0(keyagent_buffer, 1);
    buf->ref_count = 1;
    buf->bytes = g_byte_array_sized_new(size);

    if (!data) {
        g_byte_array_set_size(buf->bytes, size);
    } else {
        keyagent_buffer_append (buf, data, size);
    }
    return buf;
}

static inline keyagent_buffer_ptr
keyagent_buffer_ref(keyagent_buffer_ptr buf)
{
    g_byte_array_ref(buf->bytes);
    g_atomic_int_inc (&buf->ref_count);
    return buf;
}

static inline void
keyagent_buffer_unref(keyagent_buffer_ptr buf)
{
	if(buf != NULL)
	{
		g_byte_array_unref(buf->bytes);
		if (g_atomic_int_dec_and_test (&buf->ref_count))
			g_free(buf);
	}
}

static inline gboolean
keyagent_buffer_equal(keyagent_buffer_ptr buf1, keyagent_buffer_ptr buf2)
{
    if (keyagent_buffer_length(buf1) != keyagent_buffer_length(buf2)) return FALSE;

    return (memcmp(keyagent_buffer_data(buf1),keyagent_buffer_data(buf2), keyagent_buffer_length(buf1)) ? FALSE: TRUE);
}

typedef struct {
    keyagent_buffer_ptr		swk;
    GString                 *name;
} keyagent_session;

typedef enum {
    KEYAGENT_RSAKEY = 1,
    KEYAGENT_ECCKEY
} keyagent_keytype;


typedef struct {
	const char *certfile;
	const char *ca_certfile;
	const char *certtype;
	const char *keyname;
	const char *keytype;
} keyagent_curl_ssl_opts;

typedef struct {
	GHashTable *hash;
    gint ref_count;
} keyagent_attributes;

typedef keyagent_attributes *	keyagent_attributes_ptr;

static inline void
keyagent_attribute_free(gpointer _data)
{
    keyagent_buffer_ptr data = (keyagent_buffer_ptr)_data;
    keyagent_buffer_unref(data);
}

static inline  keyagent_attributes_ptr
keyagent_attributes_alloc() {
    keyagent_attributes_ptr ptr = g_new0(keyagent_attributes, 1);
    ptr->ref_count = 1;
    ptr->hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, keyagent_attribute_free);
    return ptr;
}

static inline keyagent_attributes_ptr
keyagent_attributes_ref(keyagent_attributes_ptr attrs)
{
    g_hash_table_ref(attrs->hash);
    g_atomic_int_inc (&attrs->ref_count);
    return attrs;
}

static inline void
keyagent_attributes_unref(keyagent_attributes_ptr attrs)
{
    g_hash_table_unref(attrs->hash);
    if (g_atomic_int_dec_and_test (&attrs->ref_count))
        g_free(attrs);
}

typedef struct {
    GString  *url;
    keyagent_keytype type;
} keyagent_key;

#define KEYAGENT_DEFINE_ATTR_QUARK(QN)                                         \
extern "C" GQuark                                                                  \
keyagent_##QN##_quark (void)                                                  \
{                                                                       \
  static GQuark q;                                                      \
                                                                        \
  if G_UNLIKELY (q == 0)                                                \
    q = g_quark_from_static_string (#QN);                               \
                                                                        \
  return q;                                                             \
}

#define KEYAGENT_ATTR_QUARK(NAME)	keyagent_##NAME##_quark()
#define KEYAGENT_DECLARE_KEY_ATTR(NAME) (KEYAGENT_ATTR_QUARK(NAME))

#ifdef NEVER
static inline const char *
KEYAGENT_ATTR_NAME_FROM_STR(const char *name)
{
	GString *tmp = g_string_new(NULL);
	g_string_printf(tmp, "KEYAGENT_ATTR_%s", name);
	const char *q = g_quark_from_static_string(tmp);
	g_string_free(tmp, TRUE);
	return q;
}
#endif

#define KEYAGENT_DEFINE_KEY_ATTRIBUTES() \
    	KEYAGENT_DEFINE_ATTR_QUARK(KEYDATA)

#define KEYAGENT_DEFINE_ATTRIBUTES() \
        KEYAGENT_DEFINE_KEY_ATTRIBUTES() \
    	KEYAGENT_DEFINE_ATTR_QUARK(IV) \
        KEYAGENT_DEFINE_ATTR_QUARK(STM_TEST_DATA) \
        KEYAGENT_DEFINE_ATTR_QUARK(STM_TEST_SIG) \
        KEYAGENT_DEFINE_ATTR_QUARK(STM_DATA) \
    	KEYAGENT_DEFINE_ATTR_QUARK(SWK) \
    	KEYAGENT_DEFINE_ATTR_QUARK(CHALLENGE_KEYTYPE) \
    	KEYAGENT_DEFINE_ATTR_QUARK(CHALLENGE_ECC_PUBLIC_KEY) \
    	KEYAGENT_DEFINE_ATTR_QUARK(CHALLENGE_RSA_PUBLIC_KEY) \
    	KEYAGENT_DEFINE_ATTR_QUARK(SW_ISSUER) \
    	KEYAGENT_DEFINE_ATTR_QUARK(SGX_ENCLAVE_ISSUER) \
    	KEYAGENT_DEFINE_ATTR_QUARK(SGX_ENCLAVE_ISSUER_PRODUCT_ID) \
    	KEYAGENT_DEFINE_ATTR_QUARK(SGX_ENCLAVE_ISSUER_EXTENDED_PRODUCT_ID) \
    	KEYAGENT_DEFINE_ATTR_QUARK(SGX_ENCLAVE_MEASUREMENT) \
    	KEYAGENT_DEFINE_ATTR_QUARK(SGX_ENCLAVE_SVN_MINIMUM_SGX_CONFIG_ID) \
    	KEYAGENT_DEFINE_ATTR_QUARK(SGX_CONFIG_ID_SVN) \
    	KEYAGENT_DEFINE_ATTR_QUARK(KPT_ISSUER)


#define KEYAGENT_ATTR_IV										KEYAGENT_DECLARE_KEY_ATTR(IV)
#define KEYAGENT_ATTR_KEYDATA									KEYAGENT_DECLARE_KEY_ATTR(KEYDATA)
#define KEYAGENT_ATTR_STM_TEST_DATA								KEYAGENT_DECLARE_KEY_ATTR(STM_TEST_DATA)
#define KEYAGENT_ATTR_STM_TEST_SIG								KEYAGENT_DECLARE_KEY_ATTR(STM_TEST_SIG)
#define KEYAGENT_ATTR_STM_DATA									KEYAGENT_DECLARE_KEY_ATTR(STM_DATA)
#define KEYAGENT_ATTR_SWK	                                    KEYAGENT_DECLARE_KEY_ATTR(SWK)
#define KEYAGENT_ATTR_CHALLENGE_KEYTYPE	                        KEYAGENT_DECLARE_KEY_ATTR(CHALLENGE_KEYTYPE)
#define KEYAGENT_ATTR_CHALLENGE_ECC_PUBLIC_KEY	                KEYAGENT_DECLARE_KEY_ATTR(CHALLENGE_ECC_PUBLIC_KEY)
#define KEYAGENT_ATTR_CHALLENGE_RSA_PUBLIC_KEY	                KEYAGENT_DECLARE_KEY_ATTR(CHALLENGE_RSA_PUBLIC_KEY)
#define KEYAGENT_ATTR_SW_ISSUER	                                KEYAGENT_DECLARE_KEY_ATTR(SW_ISSUER)
#define KEYAGENT_ATTR_SGX_ENCLAVE_ISSUER	                    KEYAGENT_DECLARE_KEY_ATTR(SGX_ENCLAVE_ISSUER)
#define KEYAGENT_ATTR_SGX_ENCLAVE_ISSUER_PRODUCT_ID	            KEYAGENT_DECLARE_KEY_ATTR(SGX_ENCLAVE_ISSUER_PRODUCT_ID)
#define KEYAGENT_ATTR_SGX_ENCLAVE_ISSUER_EXTENDED_PRODUCT_ID	KEYAGENT_DECLARE_KEY_ATTR(SGX_ENCLAVE_ISSUER_EXTENDED_PRODUCT_ID)
#define KEYAGENT_ATTR_SGX_ENCLAVE_MEASUREMENT	                KEYAGENT_DECLARE_KEY_ATTR(SGX_ENCLAVE_MEASUREMENT)
#define KEYAGENT_ATTR_SGX_ENCLAVE_SVN_MINIMUM_SGX_CONFIG_ID	    KEYAGENT_DECLARE_KEY_ATTR(SGX_ENCLAVE_SVN_MINIMUM_SGX_CONFIG_ID)
#define KEYAGENT_ATTR_SGX_CONFIG_ID_SVN	                        KEYAGENT_DECLARE_KEY_ATTR(SGX_CONFIG_ID_SVN)
#define KEYAGENT_ATTR_KPT_ISSUER	                            KEYAGENT_DECLARE_KEY_ATTR(KPT_ISSUER)

#ifdef  __cplusplus
extern "C" {
#endif

GQuark KEYAGENT_ATTR_IV;
GQuark KEYAGENT_ATTR_KEYDATA;
GQuark KEYAGENT_ATTR_STM_TEST_DATA;
GQuark KEYAGENT_ATTR_STM_TEST_SIG;
GQuark KEYAGENT_ATTR_STM_DATA;
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

#ifdef  __cplusplus
}
#endif

#define KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(ATTRS, src) do { \
	if ((src)) { \
        const gchar *keyname = g_quark_to_string ( KEYAGENT_ATTR_##src ); \
	    g_hash_table_insert((ATTRS)->hash, (gpointer) keyname,  (gpointer) keyagent_buffer_ref((src))); \
	} \
} while(0)

#define KEYAGENT_KEY_GET_BYTEARRAY_ATTR(ATTRS, NAME, DEST) do { \
    const gchar *keyname = g_quark_to_string ( KEYAGENT_ATTR_##NAME ); \
    DEST = (keyagent_buffer_ptr)g_hash_table_lookup((ATTRS)->hash, keyname); \
} while(0)

#define ENCRYPT_ATTR_HASH(VAL, SRC_ATTR, DEST_ATTRS, KEY, IV, ENCRYPT_FUNC) do { \
    keyagent_buffer_ptr tmp; \
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(SRC_ATTR, VAL, tmp); \
    keyagent_buffer_ptr VAL = keyagent_buffer_alloc(NULL, keyagent_buffer_length(tmp) + TAG_SIZE); \
	keyagent_debug_with_checksum("BEFORE-E-"#VAL, keyagent_buffer_data(tmp), keyagent_buffer_length(tmp)); \
    ENCRYPT_FUNC(tmp, KEY, IV, VAL); \
    keyagent_debug_with_checksum("AFTER-E-"#VAL, keyagent_buffer_data(VAL), keyagent_buffer_length(VAL)); \
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(DEST_ATTRS, VAL); \
    keyagent_buffer_unref(VAL); \
} while(0)

#define DECRYPT_ATTR_HASH(VAL, SRC_ATTR, DEST_ATTRS, KEY, IV, TAGLEN, DECRYPT_FUNC) do { \
    keyagent_buffer_ptr tmp; \
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(SRC_ATTR, VAL, tmp); \
    keyagent_buffer_ptr VAL = keyagent_buffer_alloc(NULL, keyagent_buffer_length(tmp) - TAGLEN); \
    keyagent_debug_with_checksum("BEFORE-D-"#VAL, keyagent_buffer_data(tmp), keyagent_buffer_length(tmp)); \
    DECRYPT_FUNC(VAL, KEY, IV, tmp, TAGLEN); \
    keyagent_debug_with_checksum("AFTER-D-"#VAL, keyagent_buffer_data(VAL), keyagent_buffer_length(VAL)); \
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(DEST_ATTRS, VAL); \
    keyagent_buffer_unref(VAL); \
} while(0)


#define COPY_ATTR_HASH(VAL, SRC_ATTR, DEST_ATTRS) do { \
    keyagent_buffer_ptr VAL; \
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(SRC_ATTR, VAL, VAL); \
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(DEST_ATTRS, VAL); \
} while(0)

#define TAG_SIZE    			16
#define AES_BLOCK_SIZE			16

#define EVP_CTRL_AEAD_SET_IVLEN 0x9
#define EVP_CTRL_AEAD_GET_TAG 	0x10
#define EVP_CTRL_AEAD_SET_TAG 	0x11
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

#endif
