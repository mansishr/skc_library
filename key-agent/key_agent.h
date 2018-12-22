#ifndef _KEYAGENT_
#define _KEYAGENT_

#include <glib.h>
#include "key-agent/types.h"

#ifdef  __cplusplus

extern "C" {
#endif

gboolean keyagent_init(const char *filename, GError **err);

void keyagent_npm_showlist();
void keyagent_stm_showlist();

keyagent_key * keyagent_loadkey(keyagent_url, GError **err);
gboolean keyagent_apimodule_register(keyagent_apimodule_ops *, GError **err);

#ifdef  __cplusplus
}
#endif


#endif
