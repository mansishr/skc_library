
#include <iostream>
#include <memory>
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "keyserver.h"
#include <jsoncpp/json/json.h>
#include <glib.h>
#include <glib/gi18n.h>
#include "k_errors.h"
#include "key-agent/types.h"
#include "key-agent/key_agent.h"
#include "key-agent/src/internal.h"


using namespace std;

extern "C" {
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>



};

#if OPENSSL_VERSION_NUMBER < 0x10100000L

extern "C" {
void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}

void RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}
};

#endif

void json_print(Json::Value &val)
{
    switch (val.type()) {
        case Json::nullValue: std::cout << "null\n"; break;
        case Json::intValue: std::cout << "int " << val.asLargestInt() << "\n"; break;
        case Json::uintValue: std::cout << "uint " << val.asLargestUInt() << "\n"; break;
        case Json::realValue: std::cout << "real " << val.asDouble() << "\n"; break;
        case Json::stringValue: std::cout << "string " << val.asString() << "\n"; break;
        case Json::booleanValue: std::cout << "boolean " << val.asBool() << "\n"; break;
        case Json::arrayValue: std::cout << "array of length " << val.size() << "\n"; break;
        case Json::objectValue: std::cout << "object of length " << val.size() << "\n"; break;
        default: std::cout << "wrong type\n"; break;
    }
}

Json::Value parse_data(std::unique_ptr<std::string> &httpData)
{
    Json::Value jsonData;
    Json::Reader jsonReader;

    if (jsonReader.parse(*httpData, jsonData))
    {
        k_debug_msg("Successfully parsed JSON data");
        k_debug_msg("SON data received:");
        k_debug_msg("%s", jsonData.toStyledString().c_str());
    }

    return jsonData;
}

std::string json_to_string(Json::Value &input) {
    Json::StreamWriterBuilder builder;
    builder.settings_["indentation"] = "";
    return Json::writeString(builder, input);
}

gchar *
generate_checksum(gchar *data, int size)
{
    return g_compute_checksum_for_data (G_CHECKSUM_SHA256, (const guchar *)data, (gsize) size);
}

void
debug_with_checksum(const gchar *label, unsigned char *buf, unsigned int size)
{
    gchar *cksum = generate_checksum((char *)buf, size);
    std::stringstream ss;
    ss << std::hex << cksum;
    std::string tmp1 = ss.str();
    k_debug_msg("%s %s\n", label, tmp1.c_str());
    g_free(cksum);
}

#define BIGNUM_FOR_ATTR_NAME(N) b_##N
#define DECLARE_BIGNUM_FOR_ATTR(N) const BIGNUM *BIGNUM_FOR_ATTR_NAME(N) = NULL

#define BN_TO_ATTR_RSA_HASH(VAL) do { \
    keyagent_buffer_ptr RSA_##VAL = keyagent_buffer_alloc(NULL, BN_num_bytes( b_##VAL)); \
    BN_bn2bin(b_##VAL, keyagent_buffer_data(RSA_##VAL)); \
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, RSA_##VAL); \
	keyagent_buffer_unref(RSA_##VAL); \
} while(0)

keyagent_key_attributes_ptr convert_key_to_attr_hash()
{
    BIGNUM *bne = NULL;
    int bits = 2048;
    unsigned long  e = RSA_F4;

    bne = BN_new();
    if (BN_set_word(bne,e) != 1) {
        BN_free(bne);
        return NULL;
    }

    RSA *rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, bits, bne, NULL) != 1) {
        RSA_free(rsa);
        BN_free(bne);
        return NULL;
    }
    BN_free(bne);

    DECLARE_BIGNUM_FOR_ATTR(N);
    DECLARE_BIGNUM_FOR_ATTR(E);
    DECLARE_BIGNUM_FOR_ATTR(D);
    DECLARE_BIGNUM_FOR_ATTR(P);
    DECLARE_BIGNUM_FOR_ATTR(Q);
    DECLARE_BIGNUM_FOR_ATTR(DP);
    DECLARE_BIGNUM_FOR_ATTR(DQ);
    DECLARE_BIGNUM_FOR_ATTR(QINV);

    RSA_get0_key(rsa, &BIGNUM_FOR_ATTR_NAME(N), &BIGNUM_FOR_ATTR_NAME(E), &BIGNUM_FOR_ATTR_NAME(D));
    RSA_get0_factors(rsa, &BIGNUM_FOR_ATTR_NAME(P), &BIGNUM_FOR_ATTR_NAME(Q));
    RSA_get0_crt_params(rsa, &BIGNUM_FOR_ATTR_NAME(DP), &BIGNUM_FOR_ATTR_NAME(DQ), &BIGNUM_FOR_ATTR_NAME(QINV));

    keyagent_key_attributes_ptr attrs = keyagent_key_alloc_attributes();

    BN_TO_ATTR_RSA_HASH(N);
    BN_TO_ATTR_RSA_HASH(E);
    BN_TO_ATTR_RSA_HASH(D);
    BN_TO_ATTR_RSA_HASH(P);
    BN_TO_ATTR_RSA_HASH(Q);
    BN_TO_ATTR_RSA_HASH(DP);
    BN_TO_ATTR_RSA_HASH(DQ);
    BN_TO_ATTR_RSA_HASH(QINV);
    RSA_free(rsa);

    return attrs;
}

#undef BN_TO_ATTR_HASH

typedef struct {
    Json::Value data;
} jsondatawrapper;

static void
attr_to_json(gpointer id, gpointer data, gpointer user_data) {
    std::string attrname = (const char *)id;
    keyagent_buffer_ptr buf = (keyagent_buffer_ptr)data;
    jsondatawrapper *datawrapper = (jsondatawrapper *)user_data;
    datawrapper->data[attrname.c_str()] = g_base64_encode(keyagent_buffer_data(buf), keyagent_buffer_length(buf));
    attrname.append("_size");
    datawrapper->data[attrname.c_str()] =  keyagent_buffer_length(buf);
}

Json::Value keyattrs_to_json(GHashTable *attr_hash)
{
    jsondatawrapper datawrapper;

    g_hash_table_foreach(attr_hash, attr_to_json, &datawrapper);
    return datawrapper.data;
}

keyagent_buffer_ptr
generate_iv()
{
    keyagent_buffer_ptr iv = keyagent_buffer_alloc(NULL, AES_BLOCK_SIZE);

    if (!RAND_bytes((unsigned char *)keyagent_buffer_data(iv), keyagent_buffer_length(iv))) {
        keyagent_buffer_unref(iv);
        iv = NULL;
        goto out;
    }

    debug_with_checksum("SERVER:CKSUM:IV", keyagent_buffer_data(iv), keyagent_buffer_length(iv));
    out:
    return iv;
}

void
print_input_headers(const char *label, const shared_ptr< Session > session)
{
    for ( const auto header : session->get_request()->get_headers( ) )
        k_debug_msg("%s Header '%s' > '%s'\n", (label ? label : ""), header.first.data( ), header.second.data( ) );
}

const gchar *
create_challenge(std::string keyid)
{
    challenge_info_t *info = new challenge_info_t();
    info->keyid = keyid;
    keyagent_real_stm *lstm = (keyagent_real_stm *)server::stm;
    const gchar *uuid = STM_MODULE_OP(lstm,challenge_generate_request)();
    g_hash_table_insert(server::uuid_hash_table, (gchar *)uuid, info);
    return uuid;
}

keyagent_buffer_ptr
decode64_json_attr(Json::Value json_data, const char *name)
{

    const char *val = json_data[name].asCString();
    gsize len = 0;
    guchar *tmp = g_base64_decode(val, &len);
    return keyagent_buffer_alloc(tmp, len);
}

void
challenge_info_free(gpointer data)
{
    challenge_info_t *info = (challenge_info_t *)data;
    if (!info) return;
    delete info;
}

void
key_info_free(gpointer data)
{
    key_info_t *info = (key_info_t *)data;
    if (!info) return;
    if (info->key_attrs) {
        g_hash_table_destroy (info->key_attrs->hash);
        g_free(info->key_attrs);
    }
    delete info;
}

extern "C" keyagent_buffer_ptr
keyagent_stm_challenge_verify(keyagent_module *stm, keyagent_buffer_ptr quote)
{
    keyagent_real_stm *lstm = (keyagent_real_stm *)stm;
    return STM_MODULE_OP(lstm,challenge_verify)(quote);
}


extern "C" keyagent_key_attributes_ptr
keyagent_stm_wrap_key(keyagent_module *stm, keyagent_keytype type, keyagent_key_attributes_ptr key_attrs)
{
    keyagent_real_stm *lstm = (keyagent_real_stm *)stm;
    keyagent_key_attributes_ptr wrapped_attrs = STM_MODULE_OP(lstm,wrap_key)(type, key_attrs);
    return wrapped_attrs;
}

extern "C"
gchar *
keyagent_generate_checksum(gchar *data, int size)
{
    return g_compute_checksum_for_data (G_CHECKSUM_SHA256, (const guchar *)data, (gsize) size);
}

extern "C" void
keyagent_debug_with_checksum(const gchar *label, unsigned char *buf, unsigned int size)
{
    gchar *tmp =  keyagent_generate_checksum((char *)buf, size);
    std::stringstream ss;
    ss << std::hex << tmp;
    std::string tmp1 = ss.str();
    k_debug_msg("%s %s\n", label, tmp1.c_str());
    g_free(tmp);
}
