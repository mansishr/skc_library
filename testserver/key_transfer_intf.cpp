

#include <iostream>
#include <memory>

#include <time.h>

#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <vector>
#include <regex>
#include <restbed>
#include <json/json.h>
#include <glib.h>
#include <glib/gi18n.h>
#include "k_errors.h"
#include "k_debug.h"
#include "key-agent/types.h"
#include "key-agent/key_agent.h"
#include "keyserver.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>


using namespace std;
using namespace restbed;
using namespace server;

extern void print_input_headers(const char *label, const shared_ptr< Session > session);

typedef struct {
	k_buffer_ptr swk;
	swk_type_op *swk_op;
}server_swk;

void
client_session_hash_value_free(gpointer data)
{
    GQuark session_id_quark = (GQuark)GPOINTER_TO_INT(data);
    g_hash_table_remove(server::session_hash_table, GINT_TO_POINTER(session_id_quark));
}

extern "C" gboolean
clear_stm_hash(gpointer key, gpointer value, gpointer user_data)
{
    return TRUE;
}

void
client_hash_value_free(gpointer data)
{
    GHashTable *stm_hash = (GHashTable *)data;
    g_hash_table_foreach_remove(stm_hash, clear_stm_hash, NULL);    
}

void
session_hash_value_free(gpointer data)
{
	//k_buffer_ptr swk = (k_buffer_ptr)data;
	server_swk *swk_info = (server_swk *)data;
	if (swk_info != (server_swk *)-1)
	{
		k_buffer_unref(swk_info->swk);
		g_free(swk_info);
	}
}

void
stm_hash_value_free(gpointer data)
{
    GQuark session_id_quark = GPOINTER_TO_INT(data);
    g_hash_table_remove(server::session_hash_table, GINT_TO_POINTER(session_id_quark));
    g_hash_table_remove(server::session_to_stm_hash_table, GINT_TO_POINTER(session_id_quark));
}

void
flush_sessions(const char *client_ip)
{
    GQuark client_ip_quark = g_quark_from_string(client_ip);
    GHashTable *stm_hash = (GHashTable *)g_hash_table_lookup(server::client_hash_table, GINT_TO_POINTER(client_ip_quark));
    if (!stm_hash) return;
    g_hash_table_foreach_remove(stm_hash, clear_stm_hash, NULL);    
}

void
set_session(const char *client_ip, const char *stmlabel, const char  *session_id, k_buffer_ptr swk, swk_type_op *op)
{
    GQuark client_ip_quark = g_quark_from_string(client_ip);
    GQuark stm_quark = g_quark_from_string(stmlabel);
    GQuark session_id_quark = g_quark_from_string(session_id);

    GHashTable *stm_hash = (GHashTable *)g_hash_table_lookup(server::client_hash_table, GINT_TO_POINTER(client_ip_quark));
    if (!stm_hash) {
        stm_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, stm_hash_value_free);
        g_hash_table_insert(server::client_hash_table, GINT_TO_POINTER(client_ip_quark), (gpointer)stm_hash);
    }

    g_hash_table_replace(stm_hash, GINT_TO_POINTER(stm_quark), GINT_TO_POINTER(session_id_quark));
    g_hash_table_insert(server::session_to_stm_hash_table, GINT_TO_POINTER(session_id_quark), GINT_TO_POINTER(stm_quark));

	//TODO need to add in session hash

    if (swk)
	{
		server_swk *swk_info = g_new0(server_swk, 1); 
		swk_info->swk = k_buffer_ref(swk);
		swk_info->swk_op = op;
        g_hash_table_insert(server::session_hash_table, GINT_TO_POINTER(session_id_quark), swk_info);
	}
    else
        g_hash_table_insert(server::session_hash_table, GINT_TO_POINTER(session_id_quark), (gpointer)-1);
}

gchar *
get_session_id(const char *client_ip, const char *stmlabel)
{
    GQuark client_ip_quark = g_quark_from_string(client_ip);
    GQuark stm_quark = g_quark_from_string(stmlabel);

    GHashTable *stm_hash = (GHashTable *)g_hash_table_lookup(server::client_hash_table, GINT_TO_POINTER(client_ip_quark));
    if (!stm_hash) return NULL;

    GQuark session_id_quark = GPOINTER_TO_INT(g_hash_table_lookup(stm_hash, GINT_TO_POINTER(stm_quark)));
    return (gchar *)g_quark_to_string(session_id_quark);
}

k_buffer_ptr
get_session_swk(const char *session_id)
{
    GQuark session_id_quark = g_quark_from_string(session_id);
    server_swk *swk = (server_swk *)g_hash_table_lookup(server::session_hash_table, GINT_TO_POINTER(session_id_quark));
	return swk->swk;
}


server_swk* get_session_swk_info(const char *session_id)
{
    GQuark session_id_quark = g_quark_from_string(session_id);
    return (server_swk *)g_hash_table_lookup(server::session_hash_table, GINT_TO_POINTER(session_id_quark));
}

const char *
get_session_stmlabel(const char *session_id)
{
    GQuark session_id_quark = g_quark_from_string(session_id);
    GQuark stm_quark = GPOINTER_TO_INT(g_hash_table_lookup(server::session_to_stm_hash_table, GINT_TO_POINTER(session_id_quark)));
    return g_quark_to_string(stm_quark);
}

void keysession_authentication_handler( const shared_ptr< Session > session, const function< void ( const shared_ptr< Session > ) >& callback )
{
    auto authorisation = session->get_request( )->get_header( "Authorization" );
    callback( session );
}

char *
get_client_ip(const shared_ptr< Session > session)
{
    char *tmp = strdup(session->get_origin().c_str());
    gint i = (rindex(tmp, ':') - tmp);
    char *tmp1 = strndup(tmp,i);
    g_free(tmp);
    return tmp1;
}

swk_type_op* get_swk_info(const char *swk_type_str)
{
        GQuark swk_id_quark = g_quark_from_string(swk_type_str);
		if( swk_id_quark == 0 )
		{
			k_critical_msg("SWK type:%s quark error\n", swk_type_str);
			return NULL;
		}
        return (swk_type_op *)g_hash_table_lookup(server::swk_type_hash, GINT_TO_POINTER(swk_id_quark));
}

char *
verify_challenge_and_encode_session(Json::Value &jsondata, const shared_ptr< Session > session, const char *session_id, const char* swk_type_str)
{
    k_buffer_ptr quote = decode64_json_attr(jsondata, "quote");
    GError *err = NULL;
	
    k_attribute_set_ptr challenge_attrs = NULL;
    if (__keyagent_stm_challenge_verify(keyagent_get_module_label(server::stm), quote, &challenge_attrs, &err)) {
        k_buffer_ptr swk = NULL;
        k_buffer_ptr sw_issuer = NULL;
        guint length;
        int i;
        k_attribute_ptr attr = NULL;
        for (i = 0, attr = challenge_attrs->attrs; i < challenge_attrs->count; ++i, ++attr) 
            k_info_msg("%d is %s", i, (attr->name ? attr->name : "NULL"));

        sw_issuer = k_attribute_set_get_attribute(challenge_attrs, (char *)"SW_ISSUER");
        char *encoded_swk = NULL;
		//TODO need to change key size
		swk_type_op  *swk_op = get_swk_info(swk_type_str);
		swk = k_buffer_alloc(NULL, swk_op->keybits/8);
        k_buffer_ptr CHALLENGE_KEYTYPE = NULL;
        CHALLENGE_KEYTYPE = k_attribute_set_get_attribute(challenge_attrs, (char *)"CHALLENGE_KEYTYPE");
        if (strcmp((const char *)k_buffer_data(CHALLENGE_KEYTYPE), "RSA") == 0) {
            k_buffer_ptr CHALLENGE_RSA_PUBLIC_KEY = NULL;
            CHALLENGE_RSA_PUBLIC_KEY = k_attribute_set_get_attribute(challenge_attrs, (char *)"CHALLENGE_RSA_PUBLIC_KEY");

            BIO* bio = BIO_new_mem_buf(k_buffer_data(CHALLENGE_RSA_PUBLIC_KEY), k_buffer_length(CHALLENGE_RSA_PUBLIC_KEY));
            RSA *rsa = d2i_RSA_PUBKEY_bio(bio, NULL);
            BIO_free(bio);

            k_buffer_ptr encrypted_swk = k_buffer_alloc(NULL, RSA_size(rsa));

            RAND_bytes((unsigned char *)k_buffer_data(swk), k_buffer_length(swk));
            int encrypt_len = RSA_public_encrypt(k_buffer_length(swk), k_buffer_data(swk), 
                k_buffer_data(encrypted_swk), rsa, server::rsa_padtype);

#ifdef WRAPDEBUG
			k_info_msg("%s:%d: rsa-size %d eswk %p/%d %d -- %x %x %x", __func__, __LINE__, RSA_size(rsa), k_buffer_data(encrypted_swk), k_buffer_length(encrypted_swk),
				encrypt_len, k_buffer_data(encrypted_swk)[0], k_buffer_data(encrypted_swk)[8], k_buffer_data(encrypted_swk)[250]);
			k_info_msg("%s:%d: rsa-size %d swk %p/%d %d -- %x %x %x", __func__, __LINE__, RSA_size(rsa), k_buffer_data(swk), k_buffer_length(swk),
				encrypt_len, k_buffer_data(swk)[0], k_buffer_data(swk)[8], k_buffer_data(swk)[15]);
#endif
            encoded_swk = g_base64_encode(k_buffer_data(encrypted_swk), k_buffer_length(encrypted_swk));
#ifdef WRAPDEBUG
			k_info_msg("%s:%d: rsa-size %d eeswk %p/%d %d -- %x %x %x", __func__, __LINE__, RSA_size(rsa), 
				k_buffer_data(encrypted_swk), k_buffer_length(encrypted_swk),
				encrypt_len, i,
				encoded_swk[0], 
				encoded_swk[8], 
				encoded_swk[250]);
#endif
            k_buffer_unref(encrypted_swk);
            if (rsa) RSA_free(rsa);
        }
        const char *stmlabel = get_session_stmlabel(session_id);
        set_session(get_client_ip(session), stmlabel, session_id, swk, swk_op);
        k_buffer_unref(swk);
        k_attribute_set_unref(challenge_attrs);
        return encoded_swk;
    } else
        return NULL;
}

void get_kms_keysession_method_handler( const shared_ptr< Session > session )
{

    const auto request			= session->get_request( );
    size_t content_length		= request->get_header( "Content-Length", 0 );

    session->fetch( content_length, [ request ]( const shared_ptr< Session > session, const Bytes & body )
    {
        const multimap< string, string > headers
                {
                        { "Content-Type", "application/json" }
                };
        int http_code = 201;

        char *swk = NULL;
        std::string http_data = String::to_string(body);
        Json::Value jsondata = parse_data(http_data);
        std::string challenge = jsondata["challenge"].asString();
        Json::Value result;
		std::string out;


        result["status"] = "Failed";
		gsize len=0;
		const gchar* challenge_str  = (const gchar *)g_base64_decode(challenge.c_str(), &len);

        GQuark session_id_quark = g_quark_from_string(challenge_str);
        if (!g_hash_table_lookup(server::session_hash_table, GINT_TO_POINTER(session_id_quark)))
        {
            k_critical_msg("invalid challenge %s", challenge.c_str());
            http_code = 401;
        } else
        {
			swk = verify_challenge_and_encode_session(jsondata, session, challenge_str, server::swk_type_str);
            if (!swk) {
                http_code = 401;
			}else
			{
				result["status"]="success";
				result["operation"]="estatblish session key";
				result["data"]["swk"] = swk;
				result["data"]["type"] = server::swk_type_str;
			}
        }
		
        out = json_to_string(result);
        session->close( http_code, out.c_str(), headers);
        if (swk) g_free(swk);

    });
}

void get_keysession_method_handler( const shared_ptr< Session > session )
{

    const auto request = session->get_request( );
    size_t content_length = request->get_header( "Content-Length", 0 );

    session->fetch( content_length, [ request ]( const shared_ptr< Session > session, const Bytes & body )
    {
        const multimap< string, string > headers
                {
                        { "Accept", "application/octet-stream"},
                        { "Content-Type", "application/json" }
                };
        int http_code = 200;

        k_debug_msg("%.*s", ( int ) body.size( ), body.data( ) );
        char *swk = NULL;
        //std::unique_ptr<std::string> http_data = std::make_unique<std::string>(String::to_string(body));
        std::string http_data = String::to_string(body);
        Json::Value jsondata = parse_data(http_data);
        std::string challenge = jsondata["challenge"].asString();
        Json::Value result;

        result["status"] = "Failed";

        GQuark session_id_quark = g_quark_from_string(challenge.c_str());
        if (!g_hash_table_lookup(server::session_hash_table, GINT_TO_POINTER(session_id_quark)))
        {
            k_critical_msg("invalid challenge %s", challenge.c_str());
            http_code = 401;
        } else
        {
            swk = verify_challenge_and_encode_session(jsondata, session, challenge.c_str(), server::swk_type_str);
            if (swk) {
                result["status"] = "ok";
                result["swk" ] = swk;
                result["type" ] = server::swk_type_str;
            } else
                http_code = 401;
        }
        std::string out = json_to_string(result);
        session->close( http_code, out.c_str(), headers);
        if (swk) g_free(swk);

    });
}

void keytransfer_authentication_handler( const shared_ptr< Session > session, const function< void ( const shared_ptr< Session > ) >& callback )
{
    auto authorisation = session->get_request( )->get_header( "Authorization" );
    callback( session );
}

Json::Value
get_challenge_info(char *client_ip, std::string keyid, int *http_code, testserver_request_type request_type)
{
    Json::Value val;
        Json::Value val1;
        Json::Value challenge_replyto;
        Json::Value link;
 	const gchar *challenge_str; 
 	gsize	len							= 0;

    *http_code							= 401;

    try {
        val["status"] = "failure";
        val["operation"] = "key transfer";

        val1["type"] = "not-authorized";
        val["faults"][0] = val1;
		challenge_str				= create_challenge(client_ip);

		if ( request_type == REQUEST_TYPE_NPM_KMS )
		{
			len							= strlen(challenge_str);
			val["challenge"]			= g_base64_encode((const guchar *)challenge_str, len);
			challenge_replyto["href"]   = g_strdup_printf("%s://testserver:%i/v1/kms/keys/session",(server::tls_auth_support)?"https":"http", server::port);
		}
		else
		{
			val["challenge"]			= challenge_str;
			challenge_replyto["href"]   = g_strdup_printf("%s://testserver:%i/keys/session",(server::tls_auth_support)?"https":"http", server::port);
		}

        val["challenge_type"]			= keyagent_get_module_label(server::stm);
        challenge_replyto["method"] = "post";

        link["challenge-replyto"] = challenge_replyto;
        val["link"] = link;


    } catch (...) {
        val["status"] = "failure";
    }
    return val;
}

static
k_buffer_ptr encrypt(k_buffer_ptr plaintext, void *swk_info_ptr, k_buffer_ptr *iv, k_buffer_ptr *ciphertext) {
	server_swk *swk_info = (server_swk *)swk_info_ptr;
	if( swk_info->swk_op->encrypt_func )
	{
		return swk_info->swk_op->encrypt_func(plaintext, swk_info_ptr, iv, ciphertext);
	}
	else 
	{
		k_critical_msg("Encrypt function not available\n");
		return NULL;
	}
}

k_buffer_ptr
aes_gcm_encrypt(k_buffer_ptr plaintext, void *swk_info_ptr, k_buffer_ptr *iv, k_buffer_ptr *ciphertext) {
	server_swk *swk_info = (server_swk *)swk_info_ptr;
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    *iv = generate_iv();
    k_debug_generate_checksum("SERVER:IV", k_buffer_data(*iv), k_buffer_length(*iv));
    *ciphertext = k_buffer_alloc(NULL, k_buffer_length(plaintext) + TAG_SIZE);

	k_debug_msg("AES:GCM-keybit:%d\n", swk_info->swk_op->keybits);
	k_buffer_ptr key = swk_info->swk;
    if (!(ctx = EVP_CIPHER_CTX_new())) return NULL;

    assert(EVP_EncryptInit_ex(ctx, swk_info->swk_op->cipher_func(), NULL, NULL, NULL) == 1);
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, k_buffer_length(*iv), NULL) == 1);
    assert(EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char *)k_buffer_data(key), (unsigned  char *)k_buffer_data(*iv)) == 1);
    assert(EVP_EncryptUpdate(ctx, k_buffer_data(*ciphertext), &len, k_buffer_data(plaintext), k_buffer_length(plaintext)) == 1);
    ciphertext_len = len;
    assert(EVP_EncryptFinal_ex(ctx, k_buffer_data(*ciphertext) + len, &len) == 1);
    ciphertext_len += len;
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, (unsigned char *) k_buffer_data(*ciphertext) + ciphertext_len) == 1);
    EVP_CIPHER_CTX_free(ctx);
	k_debug_msg("end-size %d", ciphertext_len);

    len = ciphertext_len + TAG_SIZE;
	k_buffer_set_size(*ciphertext, len);
    k_buffer_ptr input_bytes = k_buffer_alloc(NULL, sizeof(keyagent_keytransfer_t));
    keyagent_keytransfer_t *keytransfer = (keyagent_keytransfer_t *)k_buffer_data(input_bytes);
    keytransfer->iv_length = k_buffer_length(*iv);
    keytransfer->tag_size = TAG_SIZE;
    keytransfer->wrap_size = len;
    return input_bytes;
}

k_buffer_ptr
aes_cbc_encrypt(k_buffer_ptr plaintext, void *swk_info_ptr, k_buffer_ptr *iv, k_buffer_ptr *ciphertext) {

	server_swk *swk_info = (server_swk *)swk_info_ptr;
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    *iv = generate_iv();
    k_debug_generate_checksum("SERVER:IV", k_buffer_data(*iv), k_buffer_length(*iv));
    *ciphertext = k_buffer_alloc(NULL, k_buffer_length(plaintext) + TAG_SIZE);

	k_debug_msg("AES:CBC-keybit:%d\n",  swk_info->swk_op->keybits);

	k_buffer_ptr key = swk_info->swk;
	k_debug_generate_checksum("SERVER:CBC_ENCRYPT:KEY", k_buffer_data(key), k_buffer_length(key));

    if (!(ctx = EVP_CIPHER_CTX_new())) return NULL;

    assert(EVP_EncryptInit_ex(ctx, swk_info->swk_op->cipher_func(), NULL, k_buffer_data(key), k_buffer_data(*iv)) == 1);
    assert(EVP_EncryptUpdate(ctx, k_buffer_data(*ciphertext), &len, k_buffer_data(plaintext), k_buffer_length(plaintext)) == 1);
    ciphertext_len = len;
    assert(EVP_EncryptFinal_ex(ctx, k_buffer_data(*ciphertext) + len, &len) == 1);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    len = ciphertext_len + TAG_SIZE;
	k_buffer_set_size(*ciphertext, len);
    k_buffer_ptr input_bytes = k_buffer_alloc(NULL, sizeof(keyagent_keytransfer_t));
    keyagent_keytransfer_t *keytransfer = (keyagent_keytransfer_t *)k_buffer_data(input_bytes);
    keytransfer->iv_length = k_buffer_length(*iv);
    keytransfer->tag_size = TAG_SIZE;
    keytransfer->wrap_size = len;
    return input_bytes;
}

k_buffer_ptr
aes_wrap_encrypt(k_buffer_ptr plaintext, void *swk_info_ptr, k_buffer_ptr *iv, k_buffer_ptr *ciphertext) {

	server_swk *swk_info = (server_swk *)swk_info_ptr;
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len;

    *ciphertext = k_buffer_alloc(NULL, k_buffer_length(plaintext) * 2);
	k_debug_msg("AES:WRAP-keybit:%d\n",  swk_info->swk_op->keybits);

	k_buffer_ptr key = swk_info->swk;
	k_debug_generate_checksum("SERVER:WRAP_ENCRYPT:KEY", k_buffer_data(key), k_buffer_length(key));

	int wrapped_len = k_buffer_length(plaintext);
    // [PKCS#11 v2.40, 2.14.3 AES Key Wrap]
    // A key whose length is not a multiple of the AES Key Wrap block
    // size (8 bytes) will be zero padded to fit.
    int alignment = wrapped_len % 8;
    if (alignment != 0) {
        k_buffer_set_size(plaintext, wrapped_len + 8 - alignment);
        memset(&k_buffer_data(plaintext)[wrapped_len], 0, 8 - alignment);
	}

    if (!(ctx = EVP_CIPHER_CTX_new())) return NULL;
	EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    int rv = EVP_EncryptInit_ex(ctx, swk_info->swk_op->cipher_func(), NULL, k_buffer_data(key), NULL);
	if (rv != 1) {
		k_info_msg("%s:%d: %s", __func__, __LINE__, ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}
    rv = EVP_CIPHER_CTX_set_padding(ctx, 0);

	k_buffer_set_size(*ciphertext,  k_buffer_length(plaintext) + 2 * EVP_CIPHER_CTX_block_size(ctx) - 1);
	k_debug_msg("%s:%d: %p %p %d", __func__, __LINE__, k_buffer_data(*ciphertext), k_buffer_data(plaintext), k_buffer_length(plaintext)); 
    rv = EVP_EncryptUpdate(ctx, k_buffer_data(*ciphertext), &len, k_buffer_data(plaintext), k_buffer_length(plaintext));
	if (rv != 1) {
		k_info_msg("%s:%d: %s", __func__, __LINE__, ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}
    ciphertext_len = len;
    assert(EVP_EncryptFinal_ex(ctx, k_buffer_data(*ciphertext) + len, &len) == 1);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    len = ciphertext_len;
	k_buffer_set_size(*ciphertext, len);
    k_buffer_ptr input_bytes = k_buffer_alloc(NULL, sizeof(keyagent_keytransfer_t));
    keyagent_keytransfer_t *keytransfer = (keyagent_keytransfer_t *)k_buffer_data(input_bytes);
    keytransfer->iv_length = 0;
    keytransfer->tag_size = 0;
    keytransfer->wrap_size = len;
    return input_bytes;
}

static k_buffer_ptr
prepare_and_sign_cms(k_buffer_ptr input_data)
{
    k_buffer_ptr cms_bytes = NULL;
    CMS_ContentInfo *sign_cms = NULL;
    CMS_SignerInfo *si;
    BIO *input_bio = NULL;
    BIO *cms_bio = NULL;
    int flags = (CMS_PARTIAL|CMS_BINARY) & ~CMS_DETACHED;
    int ret;
    BUF_MEM *bptr = 0;

    input_bio = BIO_new(BIO_s_mem());
    BIO_write(input_bio, k_buffer_data(input_data), k_buffer_length(input_data));
    ret = BIO_get_mem_ptr(input_bio, &bptr);

    sign_cms = CMS_sign(NULL, NULL, NULL, input_bio, flags);
    si = CMS_add1_signer(sign_cms, server::cert, server::cert_key, NULL, flags);
    ret = CMS_final(sign_cms, input_bio, NULL, flags);

    cms_bio = BIO_new(BIO_s_mem());
    ret = i2d_CMS_bio_stream(cms_bio, sign_cms, input_bio, flags);
    ret = BIO_get_mem_ptr(cms_bio, &bptr);

    CMS_ContentInfo_free(sign_cms);
    cms_bytes = k_buffer_alloc(bptr->data, bptr->length);
    BIO_free(input_bio);
    BIO_free(cms_bio);
    return cms_bytes;
}

static gboolean
wrap_key(keyagent_keytype type, k_attributes_ptr attrs, server_swk *swk_info, k_buffer_ptr keydata)
{
	k_buffer_ptr swk=swk_info->swk;
    k_buffer_ptr tmp = k_buffer_ref(keydata);
    k_buffer_ptr input_bytes = NULL;
    k_buffer_ptr KEYDATA = NULL;
    keyagent_keytransfer_t *keytransfer = NULL;
	gboolean ret = FALSE;
    k_buffer_ptr wrapped_key = NULL;
    k_buffer_ptr iv = NULL;

    k_debug_generate_checksum("SERVER:PKCS8", k_buffer_data(tmp), k_buffer_length(tmp));
    input_bytes = encrypt(tmp, swk_info, &iv, &wrapped_key);
	if (!input_bytes)
		goto out;

    keytransfer = (keyagent_keytransfer_t *)k_buffer_data(input_bytes);
#ifdef WRAPDEBUG
	k_debug_msg("%s:%d: key %x %x wrapped %x %x", __func__, __LINE__,
		k_buffer_data(tmp)[0],
		k_buffer_data(tmp)[15],
		k_buffer_data(wrapped_key)[0],
		k_buffer_data(wrapped_key)[15]);
#endif
    k_debug_generate_checksum("SERVER:PKCS8:WRAPPED", k_buffer_data(wrapped_key), k_buffer_length(wrapped_key));

    if (iv)
        k_buffer_append(input_bytes, k_buffer_data(iv), k_buffer_length(iv));
    k_buffer_append(input_bytes, k_buffer_data(wrapped_key), k_buffer_length(wrapped_key));

	if (server::use_cms) {
    	k_debug_generate_checksum("SERVER:CMS:PAYLOAD", k_buffer_data(input_bytes), k_buffer_length(input_bytes));
    	KEYDATA = prepare_and_sign_cms(input_bytes);
    	k_debug_generate_checksum("SERVER:CMS", k_buffer_data(KEYDATA), k_buffer_length(KEYDATA));
	} else
		KEYDATA = k_buffer_ref(input_bytes);

    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, KEYDATA);
	ret = TRUE;
out:
    k_buffer_unref(tmp);
    k_buffer_unref(KEYDATA);
    k_buffer_unref(wrapped_key);
    k_buffer_unref(input_bytes);
    if (iv) k_buffer_unref(iv);
	return ret;
}

Json::Value
get_kms_key_info(std::string keyid, int *http_code, char *session_id)
{
    Json::Value val;
    *http_code							= 200;
    GError *err							= NULL;
    key_info_t *key_info				= (key_info_t *)g_hash_table_lookup(server::key_hash_table, keyid.c_str());

    try {
        if (!key_info) {
            key_info					= new key_info_t();
            g_hash_table_insert(server::key_hash_table, strdup(keyid.c_str()), key_info);
            key_info->key_attrs			= k_attributes_alloc();
            key_info->keytype           = convert_key_to_attr_hash((gchar *)keyid.c_str(), key_info->key_attrs, &key_info->keydata);
        }
		//TODO changing the swk encrypt data
		//k_buffer_ptr swk         = get_session_swk(session_id);
		server_swk *swk_info			= get_session_swk_info(session_id);
        if (!wrap_key(key_info->keytype, key_info->key_attrs, swk_info, key_info->keydata))
			throw "error: wrap key";
        Json::Value json_data           = keyattrs_to_json(key_info->key_attrs->hash);
		std::cout << json_data.toStyledString() << std::endl;
		//
        val["status"]					= "success";
        val["operation"]				= "key transfer";
		val["data"]["id"]				= keyid.c_str();
        val["data"]["payload"]			= json_data["KEYDATA"];
		switch (key_info->keytype) {
			case KEYAGENT_RSAKEY:
				val["data"]["key_length"]		= "2048";
        		val["data"]["algorithm"]		= "RSA";
				break;
			case KEYAGENT_ECKEY:
				val["data"]["key_length"]		= "2048";
        		val["data"]["algorithm"]		= "ECC";
				break;
			case KEYAGENT_AESKEY:
        		val["data"]["algorithm"]		= "AES";
				break;
		}
		val["data"]["policy"]["link"]
			["key-usage"]["href"]       = g_strdup_printf(
											"%s://testserver:%i/v1/key-usage-policies/073796eb-9849-4dc2-b374-18628c5635ad",
											(server::tls_auth_support)?"https":"http",server::port );
		val["data"]["policy"]["link"]
			["key-usage"]["method"]     = "get";

		val["data"]["policy"]["link"]
		["key-transfer"]["href"]        = g_strdup_printf(
											"%s://testserver:%i/v1/key-transfer-policies/a67a6747-bd53-4280-90e0-5d310ba5fed9",
											(server::tls_auth_support)?"https":"http",server::port);

		val["data"]["policy"]["link"]
			["key-transfer"]["method"]  = "get";
		time_t	current_time;
        val["data"]["created_at"]		= ctime(&current_time);
		val["data"]["type"]				= "private";

        for (auto const& id : json_data.getMemberNames())
		{
			if (strcmp(id.c_str(), "KEYDATA") == 0 )
			{
				continue;
			}
            val["data"][id]				= json_data[id];
		}
    } catch (...) {
        val["status"]					= "failure";
    }
    return val;
}

char *
validate_and_pick_session(gchar *client_ip, std::string session_ids)
{
    GList *tmp, *l = NULL;
    gint i = 0;
    gchar **ids = NULL;
    gchar *session_id = NULL;;
    gint session_cnt, random_indx;
    
	if (session_ids.empty())
        return NULL;

    ids = g_strsplit( (gchar *)(session_ids.c_str()), ",", -1);

    do {
        gchar *stmlabel;
        gchar *tmp_session_id;
        gchar **stm_session;

        if (ids[i] == NULL)
            break;

        stm_session = g_strsplit((gchar *)ids[i], ":", -1);
        stmlabel = g_strstrip(stm_session[0]);
        session_id = g_strstrip(stm_session[1]);

        tmp_session_id = get_session_id(client_ip, stmlabel);
        if (g_strcmp0(session_id, tmp_session_id) != 0) {
            k_debug_msg("%s - invalid session %s %s %p", __func__, session_id, tmp_session_id, stm_session);
            goto next;
        }
        if (get_session_swk(session_id))
            l = g_list_insert(l, (gpointer)tmp_session_id, -1);
    next:
        g_strfreev(stm_session);
        ++i;
    }while(1);
    g_strfreev(ids);

	session_cnt = g_list_length(l);
    if (!session_cnt) return NULL;
    
	random_indx = (session_cnt == 1 )?0:(rand() % (session_cnt - 1));
    session_id = (gchar *)g_list_nth(l, random_indx)->data;
    g_list_free(l);
    return session_id;
}

void get_kms_keytransfer_method_handler( const shared_ptr< Session > session )
{
        std::cout << "Calling get_kms_keytransfer_method_handler" << endl;

		size_t content_length			= 0;
		const auto request				= session->get_request();
		content_length					= request->get_header( "Content-Length", 0 ); 

		session->fetch( content_length, [ request ]( const shared_ptr< Session > session, const Bytes & body )
		{

			multimap< string, string > headers;

			Json::Value val;
			std::string keyid;
			std::string challenge;
			std::string session_ids;
			std::string out;
			std::string http_data;
			std::string rand_session_id;
			std::string request_url;
			
			request_url                 = request->get_path();

			int http_code			    = 401;

			char *client_ip			    = NULL;		
            char *session_id            = NULL;

            gchar **results             = NULL;
            gchar **results_challenge   = NULL;
            results                     = g_regex_split_simple( "/", (gchar *)request_url.c_str(), G_REGEX_RAW, G_REGEX_MATCH_NOTEMPTY);
            if ( results != NULL && *results != NULL )
                keyid                   = results[3];
			else
				keyid					= "";
			challenge					= request->get_header( "Accept-Challenge");
			session_ids					= request->get_header( "Session-ID");

            try {
			    client_ip					= get_client_ip(session);
                results_challenge           = g_regex_split_simple( ",", (gchar *)challenge.c_str(), G_REGEX_RAW, G_REGEX_MATCH_NOTEMPTY);

			    k_debug_msg("keytransfer client ip:%s\n", client_ip);


                // If client didn't send session-id, flush sessions
                if (session_ids.empty())
                    flush_sessions(client_ip); 
                else
                    session_id              = validate_and_pick_session(client_ip, session_ids);

			    //print_input_headers("TRANSFER", session);
			    headers.insert(std::make_pair("Content-Type", "application/json"));
			    http_data					= String::to_string(body);

                if (!session_id) {
                    val                     = get_challenge_info(client_ip, keyid, &http_code, REQUEST_TYPE_NPM_KMS);
                } else {
                    val                     = get_kms_key_info(keyid, &http_code, session_id);
                    headers.insert(std::make_pair(g_strdup_printf("Session-ID: %s", results_challenge[0]), session_id));
                }

			    g_free(client_ip);
			    out							= json_to_string(val);
			    session->close( http_code, out, headers);
                g_strfreev (results);
                g_strfreev (results_challenge);
            }catch(...) {
                k_critical_msg("KMS response parsing filed\n");
            }

		});
}

void get_keytransfer_method_handler( const shared_ptr< Session > session )
{
    const auto request = session->get_request( );
    size_t content_length = request->get_header( "Content-Length", 0 );


    session->fetch( content_length, [ request ]( const shared_ptr< Session > session, const Bytes & body )
    {

        Json::Value val;
        std::string keyid = request->get_header( "KeyId");
        std::string challenge = request->get_header( "Accept-Challenge");
        std::string session_ids = request->get_header( "Session-ID");
        multimap< string, string > headers;

        char *client_ip = get_client_ip(session);
        char *session_id = NULL;

        // If client didn't send session-id, flush sessions
        if (session_ids.empty())
            flush_sessions(client_ip); 
        else
            session_id = validate_and_pick_session(client_ip, session_ids);

        print_input_headers("TRANSFER", session);
        headers.insert(std::make_pair("Content-Type", "application/json"));

        int http_code = 2;
        //std::unique_ptr<std::string> http_data = std::make_unique<std::string>(String::to_string(body));
        std::string http_data = String::to_string(body);

        if (!session_id) {
            val = get_challenge_info(client_ip, keyid, &http_code, REQUEST_TYPE_NPM_REF);
        } else {
            val = get_kms_key_info(keyid, &http_code, session_id);
            headers.insert(std::make_pair("Session-ID", session_id));
        }
        g_free(client_ip);
        std::string out = json_to_string(val);
        session->close( http_code, out, headers);
    });
}
