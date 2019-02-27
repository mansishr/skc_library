
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


using namespace server;
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

X509_REQ* gen_X509Req(gchar *keyid, EVP_PKEY *pkey)
{
    int             ret = 0;
 
    int             nVersion = 1;
 
    X509_REQ        *x509_req = NULL;
    X509_NAME       *x509_name = NULL;
    BIO             *out = NULL, *bio_err = NULL;
 
    const char      *szCountry = "CA";
    const char      *szProvince = "BC";
    const char      *szCity = "Vancouver";
    const char      *szOrganization = "intel";
    const char      *szCommon = "dhsm2";
 

	GString *szPath=NULL;

	
	szPath = g_string_new(server::cert_key_path->str);
	g_string_append(szPath, "/");
	g_string_append(szPath, keyid);
	g_string_append(szPath, "_key.csr");

	k_debug_msg("Certfile :%s", szPath->str);
 
	
 
    // 2. set version of x509 req
    x509_req = X509_REQ_new();
    ret = X509_REQ_set_version(x509_req, nVersion);
    if (ret != 1){
        goto free_all;
    }
 
    // 3. set subject of x509 req
    x509_name = X509_REQ_get_subject_name(x509_req);
 
    ret = X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)szCountry, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }
 
    ret = X509_NAME_add_entry_by_txt(x509_name,"ST", MBSTRING_ASC, (const unsigned char*)szProvince, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }
 
    ret = X509_NAME_add_entry_by_txt(x509_name,"L", MBSTRING_ASC, (const unsigned char*)szCity, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }   
 
    ret = X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)szOrganization, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }
 
    ret = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)szCommon, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }
 
    // 4. set public key of x509 req
    ret = X509_REQ_set_pubkey(x509_req, pkey);
    if (ret != 1){
        goto free_all;
    }
 
    // 5. set sign key of x509 req
    ret = X509_REQ_sign(x509_req, pkey, EVP_sha1());    // return x509_req->signature->length
    if (ret <= 0){
        goto free_all;
    }
 
	k_debug_msg("Writing my CSR");	
    out = BIO_new_file(szPath->str,"w");
    ret = PEM_write_bio_X509_REQ(out, x509_req);
 
    // 6. free
free_all:
	//X509_REQ_free(x509_req);
	BIO_free_all(out);
	if(szPath) g_string_free(szPath, TRUE);

    return x509_req;
}

int gen_X509(gchar *keyid, X509_REQ *req, EVP_PKEY *pkey)
{
    int ret = 0;
    EVP_PKEY *tmppkey;
    X509V3_CTX ext_ctx;
	X509 *x509ss = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
	GString *certpath=NULL;

	certpath = g_string_new(server::cert_key_path->str);
	g_string_append(certpath, "/");
	g_string_append(certpath, keyid);
	g_string_append(certpath, "_key.cert");

	k_debug_msg("Certfile :%s", certpath->str);


	BIO *out= NULL;

    if ((x509ss = X509_new()) == NULL)
        goto end;

	if(!X509_set_version(x509ss, 2))
		goto end;

	ASN1_INTEGER_set(X509_get_serialNumber(x509ss), 1);

    if (!X509_set_issuer_name(x509ss, X509_REQ_get_subject_name(req)))
        goto end;
	X509_gmtime_adj(X509_get_notBefore(x509ss), 0);
	X509_gmtime_adj(X509_get_notAfter(x509ss), 31536000L);

    if (!X509_set_subject_name(x509ss, X509_REQ_get_subject_name(req)))
        goto end;

    tmppkey = X509_REQ_get_pubkey(req);
    if (!tmppkey || !X509_set_pubkey(x509ss, tmppkey))
        goto end;


	//X509V3_CTX                   ctx;
	//X509V3_set_ctx(&ctx, cacert, newcert, NULL, NULL, 0);
	   //X509_EXTENSION *ext;
	
	if (!X509_sign(x509ss,pkey,EVP_md5()))
        goto end;

    out = BIO_new_file(certpath->str,"w");
	PEM_write_bio_X509(out, x509ss);
    ret = 1;
end:
   BIO_free_all(out);
   X509_free(x509ss);
   if(certpath) g_string_free(certpath, TRUE);
   return ret;
}

extern "C" k_buffer_ptr
convert_rsa_key_to_attr_hash(gchar *keyid, k_attributes_ptr attrs)
{
    FILE *pfile = NULL;
    FILE *pfile_der = NULL;
    BIGNUM *bne = NULL;
    int bits = 2048;
    unsigned long  e = RSA_F4;
    unsigned int len;
    RSA *rsa = NULL;
    gboolean ret = FALSE;
    EVP_PKEY *pkey = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
	X509_REQ *req = NULL;
    k_buffer_ptr KEYDATA = NULL;
    unsigned char *tmp = NULL;
    k_buffer_ptr STM_TEST_DATA = NULL;
    k_buffer_ptr STM_TEST_SIG = NULL;
	GString *key_file = NULL;
	GString *key_file_der=NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
#endif
	ERR_load_BIO_strings();

    bne = BN_new();
    if (BN_set_word(bne,e) != 1) 
        goto out;


    rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, bits, bne, NULL) != 1)
        goto out;

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_set1_RSA(pkey, rsa))
        goto out;

	if( server::generate_cert_with_key == TRUE )
	{  
		key_file = g_string_new(server::cert_key_path->str);
		g_string_append(key_file, "/");
		g_string_append(key_file, keyid);
		g_string_append(key_file, "_key.pem");

		k_debug_msg("Key file:%s", key_file->str);

		pfile=fopen(key_file->str, "w");
		if(!pfile )
		{
			//k_critical_msg("File Open Error");	
			goto out;
		}

		if(!PEM_write_PrivateKey(pfile,pkey,NULL,NULL, 0,NULL,NULL))
		{
			//k_critical_msg("PEM_write_PrivateKey failed");	
			goto out;
		}
		req = gen_X509Req(keyid, pkey);
		if( !req )
		{
			k_critical_msg("CSR Gen fail");	
			goto out;
		}

		if(gen_X509(keyid, req, pkey) != 1)
		{
			k_critical_msg("CSR Gen fail");	
			goto out;
		}
		 
    }

    p8inf = EVP_PKEY2PKCS8(pkey);
    if (!p8inf)
        goto out;

    if ((len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL)) < 0)
        goto out;

    KEYDATA = k_buffer_alloc(NULL, len);
    tmp = k_buffer_data(KEYDATA);
	if(i2d_PKCS8_PRIV_KEY_INFO(p8inf, &tmp))
	{
		if( server::generate_cert_with_key == TRUE )
		{  
			key_file_der = g_string_new(server::cert_key_path->str);
			g_string_append(key_file_der, "/");
			g_string_append(key_file_der, keyid);
			g_string_append(key_file_der, "_key.der");
			pfile_der = fopen(key_file_der->str, "w+");
			i2d_PKCS8_PRIV_KEY_INFO_fp(pfile_der ,p8inf);
		}
	}


    STM_TEST_DATA = k_buffer_alloc(NULL, 20);
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, STM_TEST_DATA);
    STM_TEST_SIG = k_buffer_alloc(NULL, RSA_size(rsa));
    if (!RSA_sign(NID_sha1, k_buffer_data(STM_TEST_DATA), k_buffer_length(STM_TEST_DATA), 
        k_buffer_data(STM_TEST_SIG),
        &len,
        rsa)) {
        k_critical_msg("RSA_sign failed ! %s \n", ERR_error_string(ERR_get_error(), NULL));
    }
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, STM_TEST_SIG);
out:
    k_buffer_unref(STM_TEST_SIG);
    k_buffer_unref(STM_TEST_DATA);
    if (p8inf) PKCS8_PRIV_KEY_INFO_free(p8inf);
    if (pkey) EVP_PKEY_free(pkey);
    if (rsa) RSA_free(rsa);
    if (bne) BN_free(bne);
	if (key_file) g_string_free( key_file, TRUE);
	if (key_file_der) g_string_free( key_file_der, TRUE);
	if (pfile) fclose(pfile);
	if (pfile_der) fclose(pfile_der);
    X509_REQ_free(req);
    return KEYDATA;
}

k_buffer_ptr
convert_ecc_key_to_attr_hash(gchar *keyid, k_attributes_ptr attrs)
{
    EC_KEY *ec_key = NULL;
    int eccgrp;
    int len;
    unsigned char *data = NULL;
    EVP_PKEY *pkey = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    k_buffer_ptr KEYDATA = NULL;
    unsigned char *tmp = NULL;
    k_buffer_ptr STM_TEST_DATA = NULL;
    k_buffer_ptr STM_TEST_SIG = NULL;
    gboolean ret = FALSE;
    ECDSA_SIG* ec_sig = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
#endif
	ERR_load_BIO_strings();

    eccgrp = OBJ_txt2nid("secp521r1");
    ec_key = EC_KEY_new_by_curve_name(eccgrp);
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
    if (!(EC_KEY_generate_key(ec_key))) {
        k_critical_msg("Error generating the ECC key.");
        goto out;
    }

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_set1_EC_KEY(pkey, ec_key))
        goto out;

    p8inf = EVP_PKEY2PKCS8(pkey);
    if (!p8inf)
        goto out;

    if ((len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL)) < 0)
        goto out;

    KEYDATA = k_buffer_alloc(NULL, len);
    tmp = k_buffer_data(KEYDATA);
    i2d_PKCS8_PRIV_KEY_INFO(p8inf, &tmp);

    STM_TEST_DATA = k_buffer_alloc(NULL, 20);
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, STM_TEST_DATA);
    if ((ec_sig = ECDSA_do_sign(k_buffer_data(STM_TEST_DATA), k_buffer_length(STM_TEST_DATA), ec_key)) == NULL) {
        k_critical_msg("ECDSA_do_sign failed ! %s \n", ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }
    len = i2d_ECDSA_SIG(ec_sig, NULL);
    STM_TEST_SIG = k_buffer_alloc(NULL, len);
    data = (unsigned char *)k_buffer_data(STM_TEST_SIG);
    i2d_ECDSA_SIG(ec_sig, &data);
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, STM_TEST_SIG);
out:
    if (ec_sig) ECDSA_SIG_free(ec_sig);
    k_buffer_unref(STM_TEST_SIG);
    k_buffer_unref(STM_TEST_DATA);
    if (p8inf) PKCS8_PRIV_KEY_INFO_free(p8inf);
    if (pkey) EVP_PKEY_free(pkey);
    if (ec_key) EC_KEY_free(ec_key);
    return KEYDATA;
}

keyagent_keytype convert_key_to_attr_hash(gchar *keyid, k_attributes_ptr attrs, k_buffer_ptr *keydata)
{
	//TODO for checking Nginix
	if( server::generate_cert_with_key == TRUE )
	{
		*keydata = convert_rsa_key_to_attr_hash(keyid, attrs);
		return KEYAGENT_RSAKEY;
	}

    static GRand *rand = NULL;

    if (!rand)
        rand = g_rand_new();

    if (g_rand_boolean(rand)) {
        *keydata = convert_rsa_key_to_attr_hash(keyid, attrs);
        return KEYAGENT_RSAKEY;
    }
    *keydata = convert_ecc_key_to_attr_hash(keyid, attrs);
    return KEYAGENT_ECKEY;
}

typedef struct {
    Json::Value data;
    GRegex *regex;
} jsondatawrapper;

static void
attr_to_json(gpointer id, gpointer data, gpointer user_data) {
    std::string attrname = (const char *)id;
    k_buffer_ptr buf = (k_buffer_ptr)data;
    jsondatawrapper *datawrapper = (jsondatawrapper *)user_data;
    std::string tmp = g_regex_replace_literal (datawrapper->regex, attrname.c_str(), -1, 0,"", (GRegexMatchFlags)0, NULL);

    datawrapper->data[tmp.c_str()] = g_base64_encode(k_buffer_data(buf), k_buffer_length(buf));
    tmp.append("_size");
    datawrapper->data[tmp.c_str()] =  k_buffer_length(buf);
}

Json::Value keyattrs_to_json(GHashTable *attr_hash)
{
    jsondatawrapper datawrapper;
    datawrapper.regex = g_regex_new ("KEYAGENT_ATTR_", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);

    g_hash_table_foreach(attr_hash, attr_to_json, &datawrapper);
    return datawrapper.data;
}

k_buffer_ptr
generate_iv()
{
    k_buffer_ptr iv = k_buffer_alloc(NULL, AES_BLOCK_SIZE);

    if (!RAND_bytes((unsigned char *)k_buffer_data(iv), k_buffer_length(iv))) {
        k_buffer_unref(iv);
        iv = NULL;
        goto out;
    }

    k_debug_generate_checksum("SERVER:CKSUM:IV", k_buffer_data(iv), k_buffer_length(iv));
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
create_challenge(const char *client_ip)
{
	GError *err = NULL;
    keyagent_stm_real *lstm = (keyagent_stm_real *)server::stm;
    const gchar *session_id = NULL;
    if (STM_MODULE_OP(lstm,challenge_generate_request)(&session_id, &err)) {
        set_session(client_ip, keyagent_get_module_label(server::stm), session_id, NULL, NULL);
    }
    return session_id;
}

k_buffer_ptr
decode64_json_attr(Json::Value json_data, const char *name)
{

    const char *val = json_data[name].asCString();
    gsize len = 0;
    guchar *tmp = g_base64_decode(val, &len);
    return k_buffer_alloc(tmp, len);
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
__keyagent_stm_challenge_verify(const char *name, k_buffer_ptr quote, k_attribute_set_ptr *challenge_attrs, GError **error)
{
    keyagent_stm_real *lstm = (keyagent_stm_real *)server::stm;
    return STM_MODULE_OP(lstm,challenge_verify)(quote, challenge_attrs, error);
}
