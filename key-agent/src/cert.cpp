#define G_LOG_DOMAIN "keyagent-cert"

#include <stdio.h>
#include <glib.h>
#include <string>
#include <iostream>
#include <libgen.h>
#include "internal.h"
#include "k_errors.h"
#include "k_types.h"
#include "config-file/key_configfile.h"

using namespace keyagent;

extern "C" gboolean  DLL_LOCAL
__keyagent_get_certificate_files(GString *cert_filename, GString *certkey_filename, GError **err)
{
	g_return_val_if_fail( (keyagent::cert || keyagent::certkey), FALSE );
    g_string_assign(cert_filename, keyagent::cert->str);
    g_string_assign(certkey_filename, keyagent::certkey->str);
	return TRUE;
}
