#ifndef __KEYSERVER_H__
#define  __KEYSERVER_H__

#include <jsoncpp/json/json.h>
#include <memory>
#include <glib.h>
#include <restbed>
#include "key-agent/src/internal.h"
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/pem.h>


using namespace std;
using namespace restbed;

typedef enum {
	    REQUEST_TYPE_NPM_REF = 1,
		REQUEST_TYPE_NPM_KMS
} testserver_request_type;

//include <openssl/evp.h>
//

#define keyserver_attr_add_bytearray(ATTRS, src) do { \
    if ((src)) { \
        const gchar *keyname = g_quark_to_string ( ##src ); \
        g_hash_table_insert((ATTRS)->hash, (gpointer) keyname,  (gpointer) keyagent_buffer_ref((src))); \
    } \
} while(0)

extern void keytransfer_authentication_handler( const shared_ptr< Session > session, const function< void ( const shared_ptr< Session > ) >& callback );
extern void get_keytransfer_method_handler( const shared_ptr< Session > session );
extern void get_kms_keytransfer_method_handler( const shared_ptr< Session > session );
extern void keysession_authentication_handler( const shared_ptr< Session > session, const function< void ( const shared_ptr< Session > ) >& callback );
extern void get_keysession_method_handler( const shared_ptr< Session > session );
extern void get_kms_keysession_method_handler( const shared_ptr< Session > session );
/*extern void get_kms_key_usagepolicys_method_handler( const shared_ptr< Session > session );*/
extern void get_kms_key_usagepolices_method_handler( const shared_ptr< Session > session );

//extern RSA * generate_key();
//extern void wrapkey(EVP_PKEY *priv_key, DhsmWPKRSAFormat *_wpk);

void json_print(Json::Value &val);
//Json::Value parse_data(std::unique_ptr<std::string> &httpData);
Json::Value parse_data(std::string httpData);
gchar * generate_checksum(gchar *data, int size);
void debug_with_checksum(const gchar *label, unsigned char *buf, unsigned int size);
keyagent_keytype convert_key_to_attr_hash(k_attributes_ptr attrs, k_buffer_ptr *keydata);
Json::Value keyattrs_to_json(GHashTable *attr_hash);


namespace server {
    extern GHashTable *key_hash_table;
    extern GHashTable *session_hash_table;
    extern GHashTable *client_hash_table;
    extern GHashTable *session_to_stm_hash_table;
    extern GHashTable *swk_type_hash;

    extern gboolean debug;
    extern gboolean verbose;
    extern gchar *configfile;
    extern GString *configdirectory;
    extern keyagent_module *stm;
    extern X509 *cert;
    extern EVP_PKEY *cert_key;
}

typedef struct {
    std::string keyid;
} challenge_info_t;

typedef struct {
    //std::string keyid;
    k_attributes_ptr key_attrs;
    keyagent_keytype keytype;
    k_buffer_ptr keydata;
} key_info_t;

/*static const char *supported_swk_types[] = {"AES192-CTR", "AES256-CTR", "AES128-GCM", "AES192-GCM", "AES256-GCM", "AES128-CBC", */
/*"AES192-CBC", "AES256-CBC","AES128-XTS", "AES256-XTS", NULL};*/
static const char *supported_swk_types[] = { "AES128-GCM", "AES192-GCM", "AES256-GCM","AES128-CBC","AES192-CBC", "AES256-CBC", NULL};
int aes_gcm_encrypt(k_buffer_ptr plaintext, void *swk_info, k_buffer_ptr iv, k_buffer_ptr ciphertext);
int aes_cbc_encrypt(k_buffer_ptr plaintext, void *swk_info, k_buffer_ptr iv, k_buffer_ptr ciphertext);

void key_info_free(gpointer data);
void client_hash_value_free(gpointer data);
void session_hash_value_free(gpointer data);

//void *get_session_state(const char *client_ip, const char *stmlabel);
void set_session(const char *client_ip, const char *stmlabel, const char *session_id, k_buffer_ptr swk, swk_type_op *op);
gchar *get_session_id(const char *client_ip, const char *stmlabel);
const gchar *create_challenge(const char *client_ip);

const gchar *create_challenge(std::string keyid);
k_buffer_ptr decode64_json_attr(Json::Value json_data, const char *name);
k_buffer_ptr decode64_data(k_buffer_ptr ptr);

void challenge_info_free(gpointer data);

void key_info_free(gpointer data);
void print_input_headers(const char *label, const shared_ptr< Session > session);

std::string json_to_string(Json::Value &input);
k_buffer_ptr generate_iv();

#endif


