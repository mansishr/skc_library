#define G_LOG_DOMAIN "npm-kmip"
#include "key-agent/npm/npm.h"
#include <glib.h>
#include <errno.h>

const char *
xnpm_init(char *config_directory, GError **err)
{
    return "KMIP";
}
