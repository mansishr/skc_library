#define G_LOG_DOMAIN "keyagent-cert"

#include "internal.h"

using namespace keyagent;

extern "C" gboolean  DLL_LOCAL
__keyagent_get_certificate_files(GString *cert_filename, GString *certkey_filename, GError **err)
{
	if(!keyagent::cert||!keyagent::certkey) {
		g_set_error(err, KEYAGENT_ERROR,KEYAGENT_ERROR_INVALID_CERT_INFO, "Invalid Keyagent Cert info");
		return FALSE;
	}
	g_string_assign(cert_filename, keyagent::cert->str);
	g_string_assign(certkey_filename, keyagent::certkey->str);
	return TRUE;
}
