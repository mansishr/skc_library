#ifndef _KEY_CONFIGFILE_
#define _KEY_CONFIGFILE_

#include <glib.h>

#ifdef  __cplusplus
extern "C" {
#endif

void *key_config_openfile(const char *filename, GError **err);
void key_config_closefile(void *);
char *key_config_get_string(void *config, const char *section, const char *key, GError **err); 
char *key_config_get_string_optional(void *config, const char *section, const char *key, const char *default_val);
int key_config_get_integer(void *config, const char *section, const char *key, GError **err);
gboolean key_config_get_boolean(void *config, const char *section, const char *key, GError **err);
gboolean key_config_get_boolean_optional(void *config, const char *section, const char *key, gboolean default_val);

#ifdef  __cplusplus
}
#endif

#endif
