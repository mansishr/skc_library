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
gboolean keyagent_stm_get_by_name(const char *name, keyagent_module **);

GString * keyagent_session_get_ids();
gboolean keyagent_session_create(const char *name, const char *session_id, keyagent_buffer_ptr swk, const char *swk_type, gint cache_id, GError **);
gboolean keyagent_stm_set_session(keyagent_session *, GError **);
//Used by STM
GQuark keyagent_session_lookup_swktype(const char *type);
gboolean  keyagent_stm_get_challenge(const char *name, keyagent_buffer_ptr *challenge, GError **);
gboolean keyagent_stm_challenge_verify(const char *name, keyagent_buffer_ptr quote, keyagent_attributes_ptr *challenge_attrs, GError **);

int keyagent_curlsend(GString *url, GPtrArray *headers, GString *postdata, GPtrArray *response_headers, keyagent_buffer_ptr returndata, keyagent_curl_ssl_opts *ssl_opts, gboolean verbose);
gboolean keyagent_get_certificate_files(GString *cert_filename, GString *certkey_filename, GError **err);
keyagent_key * keyagent_loadkey(keyagent_url, GError **err);

gchar *keyagent_generate_checksum(gchar *data, int size);
void keyagent_debug_with_checksum(const gchar *label, unsigned char *buf, unsigned int size);

int keyagent_get_swk_keybit( GQuark swk_type );
keyagent_buffer_ptr keyagent_aes_data_decrypt(GQuark swk_type, keyagent_buffer_ptr msg, keyagent_buffer_ptr key, int tlen, keyagent_buffer_ptr iv);

gboolean keyagent_stm_load_key(keyagent_key *key, GError **error);
keyagent_session * keyagent_session_lookup(const char *session_id);
keyagent_key * keyagent_key_lookup(const char *url);
gboolean keyagent_key_free(keyagent_key *);

GQuark keyagent_key_create(keyagent_url url, keyagent_keytype type, keyagent_attributes_ptr attrs, const char *session_id, gint cache_id, GError **error);
gboolean keyagent_key_policy_add(keyagent_url url, keyagent_attributes_ptr policy_attrs, gint cache_id, GError **error);
gboolean keyagent_verify_and_extract_cms_message(keyagent_buffer_ptr msg, keyagent_buffer_ptr *data, GError **error);

#ifdef  __cplusplus
}
#endif


#endif
