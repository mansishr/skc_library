#ifndef __KEYAGENT_STM_
#define __KEYAGENT_STM_

#include <glib.h>
#include "key-agent/types.h"

typedef enum {
    APPLICATION_STM_MODE = 1,
    KEYSERVER_STM_MODE
} stm_mode;

#define DECLARE_STM_INTERFACE(NAME, RETURNTYPE, ARGS) DECLARE_KEYAGENT_INTERFACE(stm, NAME, RETURNTYPE, ARGS)
#define DECLARE_STM_OP(NAME)   DECLARE_KEYAGENT_OP(stm,NAME)
#define INIT_STM_INTERFACE(MODULE,NAME,ERROR) INIT_KEYAGENT_INTERFACE(stm,MODULE,NAME,ERROR)

DECLARE_STM_INTERFACE(init, const gchar *, (const char *config_directory, stm_mode mode, GError **err));
DECLARE_STM_INTERFACE(activate, gboolean , (GError **err));
DECLARE_STM_INTERFACE(create_challenge, gboolean, (keyagent_stm_create_challenge_details *details, GError **));
DECLARE_STM_INTERFACE(set_session, gboolean, (keyagent_stm_session_details *, GError **));
DECLARE_STM_INTERFACE(load_key, gboolean, (keyagent_stm_loadkey_details *, GError **));
DECLARE_STM_INTERFACE(challenge_generate_request, gboolean, (const gchar **, GError **));
DECLARE_STM_INTERFACE(challenge_verify, gboolean, (k_buffer_ptr quote, k_attribute_set_ptr *, GError **));
DECLARE_STM_INTERFACE(seal_key, gboolean, (keyagent_keytype type, k_attributes_ptr attrs, k_buffer_ptr *sealed_data, GError **));
DECLARE_STM_INTERFACE(unseal_key, gboolean, (keyagent_keytype type, k_buffer_ptr sealed_data, k_attributes_ptr *attrs, GError **));

typedef struct {
    DECLARE_STM_OP(init);
    DECLARE_STM_OP(activate);
    DECLARE_STM_OP(create_challenge);
    DECLARE_STM_OP(set_session);
    DECLARE_STM_OP(load_key);
    DECLARE_STM_OP(challenge_generate_request);
    DECLARE_STM_OP(challenge_verify);
    DECLARE_STM_OP(seal_key);
    DECLARE_STM_OP(unseal_key);
} stm_ops;

#define LOOKUP_STM_SWK_INTERFACES(MODULE,ERROR)

#define LOOKUP_STM_INTERFACES(MODULE,ERROR) do {\
    INIT_STM_INTERFACE(MODULE,init,ERROR); \
    INIT_STM_INTERFACE(MODULE,activate,ERROR); \
    INIT_STM_INTERFACE(MODULE,create_challenge,ERROR); \
    INIT_STM_INTERFACE(MODULE,set_session,ERROR); \
    INIT_STM_INTERFACE(MODULE,challenge_generate_request,ERROR); \
    INIT_STM_INTERFACE(MODULE,challenge_verify,ERROR); \
    LOOKUP_STM_SWK_INTERFACES(MODULE,ERROR) \
    INIT_STM_INTERFACE(MODULE,load_key,ERROR); \
    INIT_STM_INTERFACE(MODULE,seal_key,ERROR); \
    INIT_STM_INTERFACE(MODULE,unseal_key,ERROR); \
} while (0)

#define STM_MODULE_OP(MODULE,NAME)  KEYAGENT_MODULE_OP(stm,MODULE,NAME)

#endif
