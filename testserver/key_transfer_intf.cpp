

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
#include "keyserver.h"
#include <restbed>
#include <jsoncpp/json/json.h>
#include <glib.h>
#include <glib/gi18n.h>
#include "k_errors.h"
#include "key-agent/types.h"
#include "key-agent/key_agent.h"
#include "key-agent/src/internal.h"

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


typedef struct {
    int tag_len;
} stm_wrap_data;

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
    //k_info_msg("%s - %s -%s", __func__, tmp, tmp1);
    g_free(tmp);
    return tmp1;
}

char *
verify_challenge_and_encode_session(Json::Value &jsondata, const shared_ptr< Session > session, challenge_info_t *info)
{
    keyagent_buffer_ptr quote = decode64_json_attr(jsondata, "quote");
    GError *err = NULL;

    keyagent_attributes_ptr challenge_attrs = NULL;
    if (keyagent_stm_challenge_verify(keyagent_get_module_label(server::stm), quote, &challenge_attrs, &err)) {
        keyagent_buffer_ptr swk = NULL;
        keyagent_buffer_ptr sw_issuer = NULL;
        guint length;
        const char **tmp = (const char **)g_hash_table_get_keys_as_array (challenge_attrs->hash, &length);

        k_info_msg("challenge_attrs %p %d", tmp, length);
        for (int i = 0; i < length; ++i, ++tmp) 
            k_info_msg("%d is %s", i, (*tmp ? *tmp : "NULL"));
        KEYAGENT_KEY_GET_BYTEARRAY_ATTR(challenge_attrs, SW_ISSUER, sw_issuer);
        char *encoded_swk = NULL;
        swk = keyagent_buffer_alloc(NULL, AES_256_KEY_SIZE);
        keyagent_buffer_ptr CHALLENGE_KEYTYPE = NULL;
        KEYAGENT_KEY_GET_BYTEARRAY_ATTR(challenge_attrs, CHALLENGE_KEYTYPE, CHALLENGE_KEYTYPE);
        if (strcmp((const char *)keyagent_buffer_data(CHALLENGE_KEYTYPE), "RSA") == 0) {
            keyagent_buffer_ptr CHALLENGE_RSA_PUBLIC_KEY = NULL;
            KEYAGENT_KEY_GET_BYTEARRAY_ATTR(challenge_attrs, CHALLENGE_RSA_PUBLIC_KEY, CHALLENGE_RSA_PUBLIC_KEY);

            BIO* bio = BIO_new_mem_buf(keyagent_buffer_data(CHALLENGE_RSA_PUBLIC_KEY), keyagent_buffer_length(CHALLENGE_RSA_PUBLIC_KEY));
            RSA *rsa = d2i_RSA_PUBKEY_bio(bio, NULL);
            BIO_free(bio);

            keyagent_buffer_ptr encrypted_swk = keyagent_buffer_alloc(NULL, RSA_size(rsa));

            RAND_bytes((unsigned char *)keyagent_buffer_data(swk), keyagent_buffer_length(swk));
            int encrypt_len = RSA_public_encrypt(keyagent_buffer_length(swk), keyagent_buffer_data(swk), 
                keyagent_buffer_data(encrypted_swk), rsa, RSA_PKCS1_OAEP_PADDING);
            encoded_swk = g_base64_encode(keyagent_buffer_data(encrypted_swk), keyagent_buffer_length(encrypted_swk));
            keyagent_buffer_unref(encrypted_swk);
            if (rsa) RSA_free(rsa);
        }
        g_hash_table_insert(server::session_hash_table,get_client_ip(session), keyagent_buffer_ref(swk));
        keyagent_attributes_unref(challenge_attrs);
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
				//{ "Accept", "application/json"},
                        { "Content-Type", "application/json" }
                };
        int http_code = 201;

		//k_debug_msg("%.*s\n", ( int ) body.size( ), body.data( ) );
        char *swk = NULL;
        //std::unique_ptr<std::string> http_data = std::make_unique<std::string>(String::to_string(body));
        std::string http_data = String::to_string(body);
        Json::Value jsondata = parse_data(http_data);
        std::string challenge = jsondata["challenge"].asString();
        Json::Value result;
		std::string out;

        result["status"] = "Failed";
		gsize len=0;
		guchar* challenge_str  = g_base64_decode(challenge.c_str(), &len);
		k_debug_msg("Challenge in Session Establishment %s, decoded challenge:%s\n", challenge.c_str(), challenge_str);



        challenge_info_t *info = (challenge_info_t *)g_hash_table_lookup (server::uuid_hash_table, (char *)challenge_str);
        if (!info)
        {
            k_critical_msg("invalid challenge %s", challenge.c_str());
            http_code = 401;
        } else
        {
            swk = verify_challenge_and_encode_session(jsondata, session, info);
            if (!swk) {
                http_code = 401;
			}else
			{
				result["status"]="success";
				result["operation"]="estatblish session key";
				result["data"]["swk"] = swk;
			}
        }
		
        out = json_to_string(result);
        k_debug_msg("SWK: %s\n, status code:%d\n", swk, http_code);
        g_hash_table_remove(server::uuid_hash_table, challenge_str);
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

        challenge_info_t *info = (challenge_info_t *)g_hash_table_lookup (server::uuid_hash_table, challenge.c_str());
        if (!info)
        {
            k_critical_msg("invalid challenge %s", challenge.c_str());
            http_code = 401;
        } else
        {
            swk = verify_challenge_and_encode_session(jsondata, session, info);
            if (swk) {
                result["status"] = "ok";
                result["swk" ] = swk;
            } else
                http_code = 401;
        }
        g_hash_table_remove(server::uuid_hash_table, challenge.c_str());
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
get_challenge_info(std::string keyid, int *http_code, testserver_request_type request_type)
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
        val["faults"] = val1;

		if ( request_type == REQUEST_TYPE_NPM_KMS )
		{
			challenge_str				= create_challenge(keyid);
			len							= strlen(challenge_str);
			val["challenge"]			= g_base64_encode((const guchar *)challenge_str, len);
			challenge_replyto["href"] = "http://localhost:1984/v1/kms/keys/session";
		}
		else
		{
			val["challenge"]			= create_challenge(keyid);
			challenge_replyto["href"] = "http://localhost:1984/keys/session";
		}

        val["challenge_type"]			= "SW";
        challenge_replyto["method"] = "post";

        link["challenge-replyto"] = challenge_replyto;
        val["link"] = link;


    } catch (...) {
        val["status"] = "failure";
    }
    return val;
}
static
int encrypt(keyagent_buffer_ptr plaintext, keyagent_buffer_ptr key, keyagent_buffer_ptr iv, keyagent_buffer_ptr ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    assert(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1);
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, keyagent_buffer_length(iv), NULL) == 1);
    assert(EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char *)keyagent_buffer_data(key), (unsigned  char *)keyagent_buffer_data(iv)) == 1);
    assert(EVP_EncryptUpdate(ctx, keyagent_buffer_data(ciphertext), &len, keyagent_buffer_data(plaintext), keyagent_buffer_length(plaintext)) == 1);
    ciphertext_len = len;
    assert(EVP_EncryptFinal_ex(ctx, keyagent_buffer_data(ciphertext) + len, &len) == 1);
    ciphertext_len += len;
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, (unsigned char *) keyagent_buffer_data(ciphertext) + ciphertext_len) == 1);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

static keyagent_buffer_ptr
prepare_and_sign_cms(keyagent_buffer_ptr input_data)
{
    keyagent_buffer_ptr cms_bytes = NULL;
    CMS_ContentInfo *sign_cms = NULL;
    CMS_SignerInfo *si;
    BIO *input_bio = NULL;
    BIO *cms_bio = NULL;
    int flags = (CMS_PARTIAL|CMS_BINARY) & ~CMS_DETACHED;
    int ret;
    BUF_MEM *bptr = 0;

    input_bio = BIO_new(BIO_s_mem());
    BIO_write(input_bio, keyagent_buffer_data(input_data), keyagent_buffer_length(input_data));
    ret = BIO_get_mem_ptr(input_bio, &bptr);

    sign_cms = CMS_sign(NULL, NULL, NULL, input_bio, flags);
    si = CMS_add1_signer(sign_cms, server::cert, server::cert_key, NULL, flags);
    ret = CMS_final(sign_cms, input_bio, NULL, flags);

    cms_bio = BIO_new(BIO_s_mem());
    ret = i2d_CMS_bio_stream(cms_bio, sign_cms, input_bio, flags);
    ret = BIO_get_mem_ptr(cms_bio, &bptr);

    CMS_ContentInfo_free(sign_cms);
    cms_bytes = keyagent_buffer_alloc(bptr->data, bptr->length);
    BIO_free(input_bio);
    BIO_free(cms_bio);
    return cms_bytes;
}

static gboolean
wrap_key(keyagent_keytype type, keyagent_attributes_ptr attrs, keyagent_buffer_ptr swk, keyagent_buffer_ptr keydata)
{
    keyagent_buffer_ptr iv = generate_iv();
    keyagent_buffer_ptr tmp = keyagent_buffer_ref(keydata);
    keyagent_buffer_ptr wrapped_key = NULL;
    keyagent_buffer_ptr input_bytes = NULL;
    keyagent_buffer_ptr KEYDATA = NULL;
    keyagent_keytransfer_t *keytransfer = NULL;

    keyagent_debug_with_checksum("SERVER:PKCS8", keyagent_buffer_data(tmp), keyagent_buffer_length(tmp));
    keyagent_debug_with_checksum("SERVER:IV", keyagent_buffer_data(iv), keyagent_buffer_length(iv));

    wrapped_key = keyagent_buffer_alloc(NULL, keyagent_buffer_length(tmp) + TAG_SIZE);
    encrypt(tmp, swk, iv, wrapped_key);
    keyagent_debug_with_checksum("SERVER:PKCS8:WRAPPED", keyagent_buffer_data(wrapped_key), keyagent_buffer_length(wrapped_key));

    input_bytes = keyagent_buffer_alloc(NULL, sizeof(keyagent_keytransfer_t));
    keytransfer = (keyagent_keytransfer_t *)keyagent_buffer_data(input_bytes);
    keytransfer->iv_length = keyagent_buffer_length(iv);
    keytransfer->tag_size = TAG_SIZE;
    keytransfer->wrap_size = keyagent_buffer_length(wrapped_key);
    
    keyagent_buffer_append(input_bytes, keyagent_buffer_data(iv), keyagent_buffer_length(iv));
    keyagent_buffer_append(input_bytes, keyagent_buffer_data(wrapped_key), keyagent_buffer_length(wrapped_key));
    keyagent_debug_with_checksum("SERVER:CMS:PAYLOAD", keyagent_buffer_data(input_bytes), keyagent_buffer_length(input_bytes));

    KEYDATA = prepare_and_sign_cms(input_bytes);
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(attrs, KEYDATA);
    keyagent_debug_with_checksum("SERVER:CMS", keyagent_buffer_data(KEYDATA), keyagent_buffer_length(KEYDATA));
    
    keyagent_buffer_unref(tmp);
    keyagent_buffer_unref(KEYDATA);
    keyagent_buffer_unref(wrapped_key);
    keyagent_buffer_unref(input_bytes);
    keyagent_buffer_unref(iv);
}

Json::Value
get_kms_key_info(std::string keyid, int *http_code, char *client_ip)
{
    Json::Value val;
    *http_code							= 200;
    GError *err							= NULL;
    key_info_t *key_info				= (key_info_t *)g_hash_table_lookup(server::key_hash_table, keyid.c_str());

    try {
        if (!key_info) {
            key_info					= new key_info_t();
            g_hash_table_insert(server::key_hash_table, strdup(keyid.c_str()), key_info);
            key_info->key_attrs			= keyagent_attributes_alloc();
            key_info->keytype           = convert_key_to_attr_hash(key_info->key_attrs, &key_info->keydata);
        }
        keyagent_buffer_ptr swk         = (keyagent_buffer_ptr)g_hash_table_lookup(server::session_hash_table, client_ip);
        wrap_key(key_info->keytype, key_info->key_attrs, swk, key_info->keydata);
        Json::Value json_data           = keyattrs_to_json(key_info->key_attrs->hash);
		std::cout << json_data.toStyledString() << std::endl;
		//
        val["status"]					= "success";
        val["operation"]				= "key transfer";
		val["data"]["id"]				= keyid.c_str();
        val["data"]["payload"]			= json_data["KEYDATA"];
        val["data"]["algorithm"]		= (key_info->keytype == KEYAGENT_RSAKEY ? "RSA" : "ECC");
		val["data"]["key_length"]		= "2048";
		val["data"]["policy"]["link"]
			["key-usage"]["href"]       = "https://10.105.160.133/v1/key-usage-policies/073796eb-9849-4dc2-b374-18628c5635ad";

		val["data"]["policy"]["link"]
			["key-usage"]["method"]     = "get";

		val["data"]["policy"]["link"]
		["key-transfer"]["href"]        = "https://10.105.160.133/v1/key-transfer-policies/a67a6747-bd53-4280-90e0-5d310ba5fed9";

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

Json::Value
get_key_info(std::string keyid, int *http_code, char *client_ip)
{
    Json::Value val;
    *http_code = 201;
    GError *err = NULL;
    key_info_t *key_info = (key_info_t *)g_hash_table_lookup(server::key_hash_table, keyid.c_str());

    try {
        if (!key_info) {
            key_info = new key_info_t();
            g_hash_table_insert(server::key_hash_table,strdup(keyid.c_str()), key_info);
            key_info->key_attrs = keyagent_attributes_alloc();
            key_info->keytype           = convert_key_to_attr_hash(key_info->key_attrs, &key_info->keydata);
			//key_info->keytype = convert_key_to_attr_hash(key_info->key_attrs);
		}
        //keyagent_buffer_ptr IV = generate_iv();
        //KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(key_info->key_attrs, IV);
        keyagent_attributes_ptr key_attrs = NULL;
        keyagent_buffer_ptr swk = (keyagent_buffer_ptr)g_hash_table_lookup(server::session_hash_table, client_ip);
        wrap_key(key_info->keytype, key_info->key_attrs, swk, key_info->keydata);
        Json::Value json_data           = keyattrs_to_json(key_info->key_attrs->hash);
        //std::cout << json_data.toStyledString() << std::endl;
        val["algorithm"] = (key_info->keytype == KEYAGENT_RSAKEY ? "RSA" : "ECC");
        for (auto const& id : json_data.getMemberNames())
            val[id] = json_data[id];

        val["status"] = "got-it";
    } catch (...) {
        val["status"] = "failure";
    }
    return val;
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
			keyagent_buffer_ptr swk	    = NULL;

			Json::Value val;
			std::string keyid;
			std::string challenge;
			std::string session_id;
			std::string out;
			std::string http_data;
			std::string rand_session_id;

			int http_code			    = 401;

			char *client_ip			    = NULL;		
			gchar **session_ids		    = NULL;
			gint session_ids_cnt	    = 0;
			gint session_id_random		= 0;

			keyid						= "a67a6747-bd53-4280-90e0-5d310ba5fed9";
			challenge					= request->get_header( "Accept-Challenge");
			session_id					= request->get_header( "Session-ID");

			client_ip					= get_client_ip(session);
			k_debug_msg("keytransfer client ip:%s\n", client_ip);



			swk							= (keyagent_buffer_ptr)g_hash_table_lookup(server::session_hash_table, client_ip);

			// If client sent accept-challenge, they didn't have or lost session
			if (session_id.empty() && swk) {
				g_hash_table_remove(server::session_hash_table, client_ip);
				keyagent_buffer_unref(swk);
				swk = NULL;
			}

			print_input_headers("TRANSFER", session);

			if (!session_id.empty())
					{

				session_ids				= g_strsplit( (gchar *)(session_id.c_str()), ",", -1);
				session_ids_cnt			= g_strv_length (session_ids);
				session_id_random		= (session_ids_cnt == 1 )?0:(rand() % (session_ids_cnt - 1));
				rand_session_id			= std::string(session_ids[session_id_random]);
				k_debug_msg("Selected session id:%s\n", rand_session_id.c_str());

				headers.insert(std::make_pair("Content-Type", "application/json"));
				headers.insert(std::make_pair("Session-ID", rand_session_id));
				//headers					= {{ },{"Session-ID", rand_session_id}};
			}
			else
			{
				headers.insert(std::make_pair("Content-Type", "application/json"));
				//headers					= {{ "Content-Type", "application/json",}};
			}
			//std::unique_ptr<std::string> http_data = std::make_unique<std::string>(String::to_string(body));
			http_data					= String::to_string(body);

			k_debug_msg("Key Transfer swk:%p\n", swk);

			if (!swk) {
				val = get_challenge_info(keyid, &http_code, REQUEST_TYPE_NPM_KMS);
			} else {
				val = get_kms_key_info(keyid, &http_code, client_ip);
			}
			g_free(client_ip);
			out							= json_to_string(val);
			session->close( http_code, out, headers);
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

        char *client_ip = get_client_ip(session);
        k_info_msg("keytransfer %s %s", __func__, client_ip);

        keyagent_buffer_ptr swk = (keyagent_buffer_ptr)g_hash_table_lookup(server::session_hash_table, client_ip);


        // If client sent accept-challenge, they didn't have or lost session
        if (!challenge.empty() && swk) {
            g_hash_table_remove(server::session_hash_table, client_ip);
            keyagent_buffer_unref(swk);
            swk = NULL;
        }

        print_input_headers("TRANSFER", session);
        const multimap< string, string > headers
                {
                        { "Content-Type", "application/json" }
                };

        int http_code = 2;
        //std::unique_ptr<std::string> http_data = std::make_unique<std::string>(String::to_string(body));
        std::string http_data = String::to_string(body);

        if (!swk) {
            val = get_challenge_info(keyid, &http_code, REQUEST_TYPE_NPM_REF);
        } else {
            val = get_kms_key_info(keyid, &http_code, client_ip);
        }
        g_free(client_ip);
        std::string out = json_to_string(val);
        session->close( http_code, out, headers);
    });
}
