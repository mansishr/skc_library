
#ifndef STM_SGX_INTERNAL_H
#define STM_SGX_INTERNAL_H

#include <glib.h>
#include <key-agent/stm/stm.h>
#include "k_errors.h"

#ifdef  __cplusplus
extern "C" {
#endif

const char *stm_init(const char *config_directory, stm_mode mode, GError **err);
gboolean stm_activate(GError **err);
gboolean stm_create_challenge(keyagent_stm_create_challenge_details *, GError **err);
gboolean stm_set_session(keyagent_stm_session_details *details, GError **error);
gboolean stm_load_key(keyagent_stm_loadkey_details *details, GError **error);
gboolean stm_challenge_generate_request(const gchar **request, GError **error);
gboolean stm_challenge_verify(k_buffer_ptr quote, k_attribute_set_ptr *challenge_attrs, GError **error);
gboolean stm_seal_key(keyagent_keytype type, k_attributes_ptr attrs, k_buffer_ptr *sealed_data, GError **error);
gboolean stm_unseal_key(keyagent_keytype type, k_buffer_ptr sealed_data, k_attributes_ptr *wrapped_attrs, GError **error);

void application_stm_init(const char *config_directory, GError **err);
void server_stm_init(const char *config_directory, GError **err);
gboolean application_stm_activate(GError **err);
gboolean server_stm_activate(GError **err);

#define STM_ISSUER_SIZE 100

#ifdef  __cplusplus
};
#endif

#endif //STM_SGX_INTERNAL_H
