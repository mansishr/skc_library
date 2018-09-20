
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

Json::Value parse_data(std::string httpData)
{
    Json::Value jsonData;
    Json::Reader jsonReader;

    if (jsonReader.parse(httpData, jsonData))
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

gboolean convert_rsa_key_to_attr_hash(keyagent_attributes_ptr attrs)
{
    BIGNUM *bne = NULL;
    int bits = 2048;
    unsigned long  e = RSA_F4;
    unsigned int len;

    bne = BN_new();
    if (BN_set_word(bne,e) != 1) {
        BN_free(bne);
        return FALSE;
    }

    RSA *rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, bits, bne, NULL) != 1) {
        RSA_free(rsa);
        BN_free(bne);
        return FALSE;
    }
    BN_free(bne);

    len = i2d_RSAPrivateKey(rsa, NULL);
    keyagent_buffer_ptr KEYDATA = keyagent_buffer_alloc(NULL, len);
    unsigned char *tmp = keyagent_buffer_data(KEYDATA);
    i2d_RSAPrivateKey(rsa, &tmp);
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, KEYDATA);
	keyagent_buffer_unref(KEYDATA);

    keyagent_buffer_ptr STM_TEST_DATA = keyagent_buffer_alloc(NULL, 20);
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, STM_TEST_DATA);
    keyagent_buffer_ptr STM_TEST_SIG = keyagent_buffer_alloc(NULL, RSA_size(rsa));
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, STM_TEST_DATA);
    if (!RSA_sign(NID_sha1, keyagent_buffer_data(STM_TEST_DATA), keyagent_buffer_length(STM_TEST_DATA), 
        keyagent_buffer_data(STM_TEST_SIG),
        &len,
        rsa)) {
        k_critical_msg("RSA_sign failed ! %s \n", ERR_error_string(ERR_get_error(), NULL));
    }
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, STM_TEST_SIG);
    keyagent_buffer_unref(STM_TEST_SIG);
    keyagent_buffer_unref(STM_TEST_DATA);
    RSA_free(rsa);

    return TRUE;
}

gboolean convert_ecc_key_to_attr_hash(keyagent_attributes_ptr attrs)
{
    EC_KEY *ec_key = NULL;
    EVP_PKEY *pkey   = NULL;
    int eccgrp;
    int len;
    unsigned char *data;

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    eccgrp = OBJ_txt2nid("secp521r1");
    ec_key = EC_KEY_new_by_curve_name(eccgrp);
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
    if (!(EC_KEY_generate_key(ec_key))) {
        k_critical_msg("Error generating the ECC key.");
        return FALSE;
    }

    keyagent_buffer_ptr STM_TEST_DATA = keyagent_buffer_alloc(NULL, 20);
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, STM_TEST_DATA);
    ECDSA_SIG* ec_sig = NULL;
    if ((ec_sig = ECDSA_do_sign(keyagent_buffer_data(STM_TEST_DATA), keyagent_buffer_length(STM_TEST_DATA), ec_key)) == NULL) {
        k_critical_msg("ECDSA_do_sign failed ! %s \n", ERR_error_string(ERR_get_error(), NULL));
    } else {
        len = i2d_ECDSA_SIG(ec_sig, NULL);
        keyagent_buffer_ptr STM_TEST_SIG = keyagent_buffer_alloc(NULL, len);
        data = (unsigned char *)keyagent_buffer_data(STM_TEST_SIG);
        i2d_ECDSA_SIG(ec_sig, &data);
        KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, STM_TEST_SIG);
        keyagent_buffer_unref(STM_TEST_SIG);
        ECDSA_SIG_free(ec_sig);
    }
    keyagent_buffer_unref(STM_TEST_DATA);
    len = i2d_ECPrivateKey(ec_key, NULL);
    keyagent_buffer_ptr KEYDATA = keyagent_buffer_alloc(NULL, len);
    unsigned char *tmp = keyagent_buffer_data(KEYDATA);
    i2d_ECPrivateKey(ec_key, &tmp);
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, KEYDATA);
	keyagent_buffer_unref(KEYDATA);
    EC_KEY_free(ec_key);
    return TRUE;
}

keyagent_keytype convert_key_to_attr_hash(keyagent_attributes_ptr attrs)
{
    static GRand *rand = NULL;

    if (!rand)
        rand = g_rand_new();

    if (g_rand_boolean(rand)) {
        convert_rsa_key_to_attr_hash(attrs);
        return KEYAGENT_RSAKEY;
    }
    convert_ecc_key_to_attr_hash(attrs);
    return KEYAGENT_ECCKEY;
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
	GError *err = NULL;
    challenge_info_t *info = new challenge_info_t();
    info->keyid = keyid;
    keyagent_stm_real *lstm = (keyagent_stm_real *)server::stm;
    const gchar *uuid = NULL;
    STM_MODULE_OP(lstm,challenge_generate_request)(&uuid, &err);
    if (STM_MODULE_OP(lstm,challenge_generate_request)(&uuid, &err))
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

extern "C" gboolean
keyagent_stm_challenge_verify(const char *name, keyagent_buffer_ptr quote, keyagent_attributes_ptr *challenge_attrs, GError **error)
{
    keyagent_stm_real *lstm = (keyagent_stm_real *)server::stm;
    return STM_MODULE_OP(lstm,challenge_verify)(quote, challenge_attrs, error);
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
