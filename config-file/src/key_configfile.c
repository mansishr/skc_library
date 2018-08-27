#define G_LOG_DOMAIN "key-configfile"
#include "config-file/key_configfile.h"
#include <glib.h>
#include <k_errors.h>
#include <errno.h>

void
key_config_closefile(void *config)
{
	if (config)
	{
		g_key_file_free((GKeyFile *)config);
	}
}

void *
key_config_openfile(const char *filename, GError **err)
{

	g_return_val_if_fail ((err == NULL || *err == NULL) && filename, NULL);

	GKeyFile *key_file = g_key_file_new();
	g_return_val_if_fail (key_file, NULL);

	GError *error = NULL;
	k_debug_msg("file - %s\n", filename);
	if (!g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, &error))
  	{
		g_key_file_free(key_file);
		key_file = NULL;
    		if (!g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
		{
      			k_critical_error(error);
		} 
		g_propagate_error (err, error);
	}
	else
	{
		g_key_file_set_list_separator (key_file, ',');
	}
	return (void*)key_file;
}

char *
key_config_get_string(void *config, const char *section, const char *key, GError **err)
{
	g_return_val_if_fail (err == NULL || *err == NULL , NULL);
	return g_key_file_get_string((GKeyFile *)config, section, key, err);
}

char **
key_config_get_string_list(void *config, const char *section, const char *key, GError **err)
{
	g_return_val_if_fail (err == NULL || *err == NULL , NULL);
	return g_key_file_get_string_list((GKeyFile *)config, section, key, NULL, err);
}

char *
key_config_get_string_optional(void *config, const char *section, const char *key, char *default_val)
{
	g_autoptr(GError) err = NULL;
	char *val = key_config_get_string(config, section, key, &err);
	if (err != NULL)
		val = default_val;
	return val;
}

int
key_config_get_integer(void *config, const char *section, const char *key, GError **err)
{
	g_return_val_if_fail (err == NULL || *err == NULL , -1);
	return g_key_file_get_integer((GKeyFile *)config, section, key, err);
}

int
key_config_get_integer_optional(void *config, const char *section, const char *key, int default_val)
{
	g_autoptr(GError) err = NULL;
	int val = key_config_get_integer(config, section, key, &err);
	if (err != NULL)
		val = default_val;
	return val;
}

int
key_config_get_boolean(void *config, const const char *section, const char *key, GError **err)
{
    g_return_val_if_fail (err == NULL || *err == NULL , -1);
    return g_key_file_get_boolean((GKeyFile *)config, section, key, err);
}

int
key_config_get_boolean_optional(void *config, const char *section, const char *key, gboolean default_val)
{
    g_autoptr(GError) err = NULL;
    int val = key_config_get_boolean(config, section, key, &err);
    if (err != NULL)
        val = default_val;
    return val;
}
