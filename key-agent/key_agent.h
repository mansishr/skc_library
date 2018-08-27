#ifndef _KEYAGENT_
#define _KEYAGENT_

#include <glib.h>
#include "key-agent/types.h"
#include "key-agent/stm/stm.h"

#ifdef  __cplusplus

extern "C" {
#endif

gboolean keyagent_init(const char *filename, GError **err);

void keyagent_npm_showlist();
void keyagent_stm_showlist();

GString *keyagent_stm_get_names();
keyagent_module * keyagent_stm_get_by_name(const char *name);
void keyagent_stm_set_session(keyagent_module *stm, keyagent_buffer_ptr swk);
keyagent_buffer_ptr  keyagent_stm_get_challenge(keyagent_module *stm);

keyagent_buffer_ptr keyagent_stm_challenge_verify(keyagent_module *stm, keyagent_buffer_ptr quote);

int keyagent_curlsend(GString *url, GPtrArray *headers, GString *postdata, keyagent_buffer_ptr returndata, keyagent_curl_ssl_opts *ssl_opts, gboolean verbose);
gboolean keyagent_get_certificate_files(GString *cert_filename, GString *certkey_filename, GError **err);

keyagent_keyid keyagent_loadkey(keyagent_url, GError **err);

static inline  keyagent_key_attributes_ptr
keyagent_key_alloc_attributes() {
    keyagent_key_attributes_ptr ptr = g_new0(keyagent_key_attributes, 1);
    ptr->hash = g_hash_table_new (g_str_hash, g_str_equal);
    return ptr;
}

gchar *keyagent_generate_checksum(gchar *data, int size);
void keyagent_debug_with_checksum(const gchar *label, unsigned char *buf, unsigned int size);

keyagent_buffer_ptr keyagent_aes_gcm_data_decrypt(keyagent_buffer_ptr msg, keyagent_buffer_ptr key, int tlen, keyagent_buffer_ptr iv);

void keyagent_key_set_type(keyagent_key *, keyagent_keytype type, keyagent_key_attributes_ptr attributes);
void keyagent_key_set_stm(keyagent_key *, keyagent_module *stm);

keyagent_key_attributes_ptr keyagent_stm_wrap_key(keyagent_module *stm, keyagent_keytype type, keyagent_key_attributes_ptr key_attrs);

gboolean keyagent_stm_load_key(keyagent_key *key);

#ifdef  __cplusplus
}
#endif


#endif
