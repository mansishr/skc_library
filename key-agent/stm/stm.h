#ifndef __KEYAGENT_STM_
#define __KEYAGENT_STM_

#include <glib.h>

typedef struct {
    GString *name;
} keyagent_stm;

typedef void (* stm_init_func) (keyagent_stm *, GError **err);

#endif

