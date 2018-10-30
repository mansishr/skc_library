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

extern void keytransfer_authentication_handler( const shared_ptr< Session > session, const function< void ( const shared_ptr< Session > ) >& callback );
extern void get_keytransfer_method_handler( const shared_ptr< Session > session );
extern void get_kms_keytransfer_method_handler( const shared_ptr< Session > session );
extern void keysession_authentication_handler( const shared_ptr< Session > session, const function< void ( const shared_ptr< Session > ) >& callback );
extern void get_keysession_method_handler( const shared_ptr< Session > session );
extern void get_kms_keysession_method_handler( const shared_ptr< Session > session );

//extern RSA * generate_key();
//extern void wrapkey(EVP_PKEY *priv_key, DhsmWPKRSAFormat *_wpk);

void json_print(Json::Value &val);
//Json::Value parse_data(std::unique_ptr<std::string> &httpData);
Json::Value parse_data(std::string httpData);
gchar * generate_checksum(gchar *data, int size);
void debug_with_checksum(const gchar *label, unsigned char *buf, unsigned int size);
keyagent_keytype convert_key_to_attr_hash(keyagent_attributes_ptr attrs, keyagent_buffer_ptr *keydata);
Json::Value keyattrs_to_json(GHashTable *attr_hash);


namespace server {
    extern GHashTable *uuid_hash_table;
    extern GHashTable *key_hash_table;
    extern GHashTable *session_hash_table;

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
    keyagent_attributes_ptr key_attrs;
    keyagent_keytype keytype;
    keyagent_buffer_ptr keydata;
} key_info_t;

void challenge_info_free(gpointer data);
void key_info_free(gpointer data);

const gchar *create_challenge(std::string keyid);
keyagent_buffer_ptr decode64_json_attr(Json::Value json_data, const char *name);
keyagent_buffer_ptr decode64_data(keyagent_buffer_ptr ptr);

void challenge_info_free(gpointer data);

void key_info_free(gpointer data);
void print_input_headers(const char *label, const shared_ptr< Session > session);

std::string json_to_string(Json::Value &input);
keyagent_buffer_ptr generate_iv();

#endif


