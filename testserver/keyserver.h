#ifndef __KEYSERVER_H__
#define  __KEYSERVER_H__

#include <jsoncpp/json/json.h>
#include <memory>
#include <glib.h>
#include <restbed>
#include "key-agent/src/internal.h"

using namespace std;
using namespace restbed;

//include <openssl/evp.h>

extern void keytransfer_authentication_handler( const shared_ptr< Session > session, const function< void ( const shared_ptr< Session > ) >& callback );
extern void get_keytransfer_method_handler( const shared_ptr< Session > session );
extern void keysession_authentication_handler( const shared_ptr< Session > session, const function< void ( const shared_ptr< Session > ) >& callback );
extern void get_keysession_method_handler( const shared_ptr< Session > session );

//extern RSA * generate_key();
//extern void wrapkey(EVP_PKEY *priv_key, DhsmWPKRSAFormat *_wpk);

void json_print(Json::Value &val);
//Json::Value parse_data(std::unique_ptr<std::string> &httpData);
Json::Value parse_data(std::string httpData);
gchar * generate_checksum(gchar *data, int size);
void debug_with_checksum(const gchar *label, unsigned char *buf, unsigned int size);
keyagent_key_attributes_ptr convert_key_to_attr_hash();
Json::Value keyattrs_to_json(GHashTable *attr_hash);


namespace server {
    extern GHashTable *uuid_hash_table;
    extern GHashTable *key_hash_table;
    extern gboolean debug;
    extern gboolean verbose;
    extern gchar *configfile;
    extern GString *configdirectory;
    //xxextern keyagent_real_stm *stm;
    extern keyagent_module *stm;
}

typedef struct {
    std::string keyid;
} challenge_info_t;

typedef struct {
    std::string keyid;
    keyagent_key_attributes_ptr key_attrs;
    keyagent_buffer_ptr swk;
} key_info_t;

void challenge_info_free(gpointer data);
void key_info_free(gpointer data);

const gchar *create_challenge(std::string keyid);
keyagent_buffer_ptr decode64_json_attr(Json::Value json_data, const char *name);

void challenge_info_free(gpointer data);

void key_info_free(gpointer data);
void print_input_headers(const char *label, const shared_ptr< Session > session);

std::string json_to_string(Json::Value &input);
keyagent_buffer_ptr generate_iv();

#endif


