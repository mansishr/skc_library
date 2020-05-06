#define G_LOG_DOMAIN "keyagent-npm"

#include "../src/internal.h"

using namespace keyagent;

extern "C" void DLL_LOCAL
__initialize_npm(gpointer data, gpointer user_data)
{
	const char *filename = (const char *)data;
	keyagent_npm_real *npm = g_new0(keyagent_npm_real, 1);
	npm->key_queue = g_queue_new();
	npm->module_name = g_string_new(filename);

	g_autoptr(GError) tmp_error = NULL;
	const char *name = NULL;

	npm->module = g_module_open(npm->module_name->str, G_MODULE_BIND_LAZY);
	if(!npm->module)
	{
		g_set_error(&tmp_error, KEYAGENT_ERROR, KEYAGENT_ERROR_NPMLOAD,
			"%s", g_module_error ());
		k_critical_msg(tmp_error);
		goto errexit;
	}
	LOOKUP_NPM_INTERFACES(npm, KEYAGENT_ERROR_NPMLOAD);

	name = NPM_MODULE_OP(npm,init)(keyagent::configdirectory->str, &tmp_error);
	if(!name)
		goto errexit;
	keyagent_set_module_label(npm,name);
	npm->initialized = 1;
	g_hash_table_insert(keyagent::npm_hash, keyagent_get_module_label(npm), npm);
	return;
errexit:
	if(npm->module)
	{
		if(!g_module_close(npm->module))
			g_warning ("%s: %s", filename, g_module_error ());
	}
	npm->module = NULL;
	k_critical_msg ("Error loading npm - %s: %s", filename, tmp_error->message);
	return;
}

DLL_LOCAL void
__show_npms(gpointer key, gpointer data, gpointer user_data)
{
	keyagent_npm_real *npm = (keyagent_npm_real *)data;
	g_print("NPM - %s (%s) - %s\n", keyagent_get_module_label(npm),
	(npm->initialized ? "Initialized" : "Failed"), npm->module_name->str);
}

extern "C" void DLL_PUBLIC
keyagent_npm_showlist()
{
	g_print("\n");
	g_hash_table_foreach(keyagent::npm_hash, __show_npms, NULL);
}
