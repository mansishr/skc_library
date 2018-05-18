#ifndef __KEYAGENT_NPM_
#define __KEYAGENT_NPM_

#include <glib.h>

typedef struct {
    GString *name;
    GString *url;
} keyagent_npm;

typedef struct {
	GQuark	id;
} keyagent_npm_key;

typedef void (* npm_init_func) (keyagent_npm *, GError **err);
typedef keyagent_npm_key * (* npm_key_init_func) (keyagent_npm *, void *config, GQuark id, GError **err);

#endif

