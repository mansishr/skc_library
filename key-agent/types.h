#ifndef _KEYAGENT_TYPES_
#define _KEYAGENT_TYPES_

#include <glib.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    GString *label;
} keyagent_module;

#define keyagent_get_module_label(MODULE) ((keyagent_module *)(MODULE))->label->str

#define keyagent_set_module_label(MODULE,LABEL) do { \
	((keyagent_module *)(MODULE))->label = g_string_new((LABEL)); \
} while(0)

typedef gchar * keyagent_url;
typedef GQuark keyagent_keyid;

#define keyagent_keyid_from_url(url) g_quark_from_string ((url))

typedef struct {
	GByteArray *bytes;
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
    return buf;
}

static inline void
keyagent_buffer_unref(keyagent_buffer_ptr buf)
{
	g_byte_array_unref(buf->bytes);
}



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
} keyagent_key_attributes;

typedef keyagent_key_attributes *	keyagent_key_attributes_ptr;

typedef struct {
	keyagent_keyid id;
    keyagent_keytype type;
    //keyagent_buffer_ptr iv;
    GString  *url;
    //int tag_length;
    keyagent_module *stm;
	keyagent_key_attributes_ptr attributes;
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
    	KEYAGENT_DEFINE_ATTR_QUARK(IV) \
    	KEYAGENT_DEFINE_ATTR_QUARK(RSA_N) \
    	KEYAGENT_DEFINE_ATTR_QUARK(RSA_E) \
    	KEYAGENT_DEFINE_ATTR_QUARK(RSA_D) \
    	KEYAGENT_DEFINE_ATTR_QUARK(RSA_P) \
    	KEYAGENT_DEFINE_ATTR_QUARK(RSA_Q) \
    	KEYAGENT_DEFINE_ATTR_QUARK(RSA_DP) \
    	KEYAGENT_DEFINE_ATTR_QUARK(RSA_DQ) \
    	KEYAGENT_DEFINE_ATTR_QUARK(RSA_QINV) \
        KEYAGENT_DEFINE_ATTR_QUARK(STM_DATA)


#define KEYAGENT_ATTR_IV	    KEYAGENT_DECLARE_KEY_ATTR(IV)
#define KEYAGENT_ATTR_RSA_N	    KEYAGENT_DECLARE_KEY_ATTR(RSA_N)
#define KEYAGENT_ATTR_RSA_E	    KEYAGENT_DECLARE_KEY_ATTR(RSA_E)
#define KEYAGENT_ATTR_RSA_D	    KEYAGENT_DECLARE_KEY_ATTR(RSA_D)
#define KEYAGENT_ATTR_RSA_P	    KEYAGENT_DECLARE_KEY_ATTR(RSA_P)
#define KEYAGENT_ATTR_RSA_Q	    KEYAGENT_DECLARE_KEY_ATTR(RSA_Q)
#define KEYAGENT_ATTR_RSA_DP	KEYAGENT_DECLARE_KEY_ATTR(RSA_DP)
#define KEYAGENT_ATTR_RSA_DQ	KEYAGENT_DECLARE_KEY_ATTR(RSA_DQ)
#define KEYAGENT_ATTR_RSA_QINV	KEYAGENT_DECLARE_KEY_ATTR(RSA_QINV)
#define KEYAGENT_ATTR_STM_DATA	KEYAGENT_DECLARE_KEY_ATTR(STM_DATA)


#ifdef  __cplusplus
extern "C" {
#endif

GQuark KEYAGENT_ATTR_IV;
GQuark KEYAGENT_ATTR_RSA_N;
GQuark KEYAGENT_ATTR_RSA_E;
GQuark KEYAGENT_ATTR_RSA_D;
GQuark KEYAGENT_ATTR_RSA_P;
GQuark KEYAGENT_ATTR_RSA_Q;
GQuark KEYAGENT_ATTR_RSA_DP;
GQuark KEYAGENT_ATTR_RSA_DQ;
GQuark KEYAGENT_ATTR_RSA_QINV;
GQuark KEYAGENT_ATTR_STM_DATA;


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
    DEST = (keyagent_buffer_ptr)g_hash_table_lookup(attrs->hash, keyname); \
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

#define DECLARE_KEYAGENT_INTERFACE(SUBTYPE, NAME, RETURNTYPE, ARGS) \
    typedef RETURNTYPE (* SUBTYPE##_##NAME##_func) ARGS

#define DECLARE_KEYAGENT_OP(SUBTYPE,NAME) \
    SUBTYPE##_##NAME##_func SUBTYPE##_func_##NAME

#define INIT_KEYAGENT_INTERFACE(SUBTYPE,MODULE,NAME,ERROR) \
    KEYAGENT_MODULE_LOOKUP((MODULE)->module, #SUBTYPE"_"#NAME, (MODULE)->ops.SUBTYPE##_func_##NAME, (ERROR))


#define KEYAGENT_MODULE_OP(SUBTYPE,MODULE,NAME)  (MODULE)->ops.SUBTYPE##_func_##NAME

#endif
