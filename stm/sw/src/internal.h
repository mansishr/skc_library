
#ifndef STM_SW_INTERNAL_H
#define STM_SW_INTERNAL_H

#include <glib.h>
#include <key-agent/stm/stm.h>
#include <openssl/err.h>
#include "k_errors.h"


typedef struct {
    int tag_len;
} stm_wrap_data;

#ifdef  __cplusplus
extern "C" {
#endif

void application_stm_init(const char *config_directory, GError **err);
void server_stm_init(const char *config_directory, GError **err);
gboolean application_stm_activate(GError **err);
gboolean server_stm_activate(GError **err);

static inline void stm_log_openssl_error(const char *label)
{
    char err[300];
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    k_critical_msg("%s: %s", label, err);
}

#define STM_ISSUER_SIZE 100

#ifdef  __cplusplus
};
#endif

#endif //STM_SW_INTERNAL_H
