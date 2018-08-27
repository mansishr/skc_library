#define G_LOG_DOMAIN "keyagent-cert"

#include <string>
#include <iostream>
#include <libgen.h>
#include "internal.h"
#include "config-file/key_configfile.h"

using namespace keyagent;

extern "C" gboolean 
keyagent_get_certificate_files(GString *cert_filename, GString *certkey_filename, GError **err)
{
    g_string_assign(cert_filename, keyagent::cert->str);
    g_string_assign(certkey_filename, keyagent::certkey->str);
	return TRUE;
}
