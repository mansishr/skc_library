#ifndef _KEY_CONFIGFILE_
#define _KEY_CONFIGFILE_

#include <errno.h>
#include <glib.h>

#ifdef  __cplusplus
extern "C" {
#endif

void *key_config_openfile(const char *filename, GError **err);
void key_config_closefile(void *);
char *key_config_get_string(void *config, char *section, const char *key, GError **err); 
char **key_config_get_string_list(void *config, char *section, const char *key, GError **err); 
char *key_config_get_string_optional(void *config, char *section, const char *key, char *default_val);
int key_config_get_integer(void *config, char *section, const char *key, GError **err);
int key_config_get_integer_optional(void *config, char *section, const char *key, int default_val);

#ifdef  __cplusplus
}
#endif

#endif
