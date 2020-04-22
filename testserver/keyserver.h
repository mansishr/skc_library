#ifndef __KEYSERVER_H__
#define  __KEYSERVER_H__

#include "k_types.h"
#include <json/json.h>
#include <memory>
#include <glib.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <gmodule.h>
#include "key-agent/types.h"
#include "key-agent/stm/stm.h"

using namespace std;

typedef enum {
	REQUEST_TYPE_NPM_REF = 1,
	REQUEST_TYPE_NPM_KMS
}testserver_request_type;

typedef struct {
    keyagent_module stm;
    GString *module_name;
    GModule *module;
    gint initialized:1;
    stm_ops ops;
}keyagent_stm_real;

#define STM_MODULE_OP(MODULE,NAME) KEYAGENT_MODULE_OP(stm,MODULE,NAME)

typedef struct swk_op {
	int keybits;
	const EVP_CIPHER* (* cipher_func )(void);
	k_buffer_ptr (* encrypt_func)(k_buffer_ptr plaintext, void *swk_info, k_buffer_ptr *iv, k_buffer_ptr *ciphertext);
	k_buffer_ptr (* decrypt_func)(struct swk_op *swk_op, k_buffer_ptr msg, k_buffer_ptr key, int tlen, k_buffer_ptr iv);
}swk_type_op;

#define keyserver_attr_add_bytearray(ATTRS, src) do { \
	if((src)) { \
		const gchar *keyname = g_quark_to_string(##src); \
		g_hash_table_insert((ATTRS)->hash, (gpointer) keyname, (gpointer)keyagent_buffer_ref((src))); \
	} \
}while(0)

void json_print(Json::Value &val);
Json::Value parse_data(std::string httpData);
gchar * generate_checksum(gchar *data, int size);
void debug_with_checksum(const gchar *label, unsigned char *buf, unsigned int size);
keyagent_keytype convert_key_to_attr_hash(gchar *keyid, k_attributes_ptr attrs, k_buffer_ptr *keydata);
Json::Value keyattrs_to_json(GHashTable *attr_hash);

namespace server {
	extern GHashTable *key_hash_table;
	extern GHashTable *session_hash_table;
	extern GHashTable *client_hash_table;
	extern GHashTable *session_to_stm_hash_table;
	extern GHashTable *swk_type_hash;
	extern const char *swk_type_str;
	extern keyagent_keytype	keytype;
	extern gint	rsa_padtype;
	extern gboolean debug;
	extern gboolean verbose;
	extern gboolean use_cms;
	extern gboolean tls_auth_support;
	extern gchar *configfile;
	extern GString *configdirectory;
	extern keyagent_module *stm;
	extern X509 *cert;
	extern EVP_PKEY *cert_key;
	extern gboolean generate_cert_with_key;
	extern GString *cert_key_path;
	extern GString *stm_filename;
	extern gint port;
}

typedef struct {
	std::string keyid;
}challenge_info_t;

typedef struct {
	k_attributes_ptr key_attrs;
	keyagent_keytype keytype;
	k_buffer_ptr keydata;
}key_info_t;

k_buffer_ptr aes_gcm_encrypt(k_buffer_ptr plaintext, void *swk_info, k_buffer_ptr *iv, k_buffer_ptr *ciphertext);
k_buffer_ptr aes_cbc_encrypt(k_buffer_ptr plaintext, void *swk_info, k_buffer_ptr *iv, k_buffer_ptr *ciphertext);
k_buffer_ptr aes_wrap_encrypt(k_buffer_ptr plaintext, void *swk_info, k_buffer_ptr *iv, k_buffer_ptr *ciphertext);
void key_info_free(gpointer data);
void client_hash_value_free(gpointer data);
void session_hash_value_free(gpointer data);
void set_session(const char *client_ip, const char *stmlabel, const char *session_id, k_buffer_ptr swk, swk_type_op *op);
gchar *get_session_id(const char *client_ip, const char *stmlabel);
const gchar *create_challenge(const char *client_ip);
const gchar *create_challenge(std::string keyid);
k_buffer_ptr decode64_json_attr(Json::Value json_data, const char *name);
k_buffer_ptr decode64_data(k_buffer_ptr ptr);
void challenge_info_free(gpointer data);
void key_info_free(gpointer data);
std::string json_to_string(Json::Value &input);
k_buffer_ptr generate_iv();
swk_type_op* get_swk_info(const char *swk_type_str);

#endif
