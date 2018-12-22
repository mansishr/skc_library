#ifndef __KEYAGENT_NPM_
#define __KEYAGENT_NPM_

#include <glib.h>
#include <key-agent/types.h>

#define DECLARE_NPM_INTERFACE(NAME, RETURNTYPE, ARGS) DECLARE_KEYAGENT_INTERFACE(npm, NAME, RETURNTYPE, ARGS)

#define DECLARE_NPM_OP(NAME)   DECLARE_KEYAGENT_OP(npm,NAME)

#define INIT_NPM_INTERFACE(MODULE,NAME,ERROR) INIT_KEYAGENT_INTERFACE(npm,MODULE,NAME,ERROR)

DECLARE_NPM_INTERFACE(init, const gchar *, (const char *config_directory, GError **err));
DECLARE_NPM_INTERFACE(register, gboolean, (keyagent_url, GError **));
DECLARE_NPM_INTERFACE(key_load, gboolean, (keyagent_keyload_details * , GError **err));
DECLARE_NPM_INTERFACE(finalize, void, (GError **err));

typedef struct {
    DECLARE_NPM_OP(init);
    DECLARE_NPM_OP(register);
    DECLARE_NPM_OP(key_load);
    DECLARE_NPM_OP(finalize);
} npm_ops;

#define LOOKUP_NPM_INTERFACES(MODULE,ERROR) do {\
    INIT_NPM_INTERFACE(MODULE,init,ERROR); \
    INIT_NPM_INTERFACE(MODULE,register,ERROR); \
    INIT_NPM_INTERFACE(MODULE,key_load,ERROR); \
    INIT_NPM_INTERFACE(MODULE,finalize,ERROR); \
} while (0)

#define NPM_MODULE_OP(MODULE,NAME)  KEYAGENT_MODULE_OP(npm,MODULE,NAME)


#endif
