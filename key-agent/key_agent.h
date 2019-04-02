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

gboolean keyagent_loadkey_with_moduledata(keyagent_url, void *module_data, GError **err);

#define keyagent_loadkey(URL,ERR)	keyagent_loadkey_with_moduledata((URL), NULL, (ERR))

gboolean keyagent_apimodule_register(keyagent_apimodule_ops *, GError **err);

#ifdef  __cplusplus
}
#endif


#endif
