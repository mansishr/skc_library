#include <memory>
#include <restbed>
#include <cstdlib>
#include <ciso646>
#include <functional>
#include "keyserver.h"
#include <glib.h>
#include "config-file/key_configfile.h"
#include "k_errors.h"
#include "key-agent/types.h"
#include "config.h"

#define KEYAGENT_MODULE_LOOKUP(MODULE,FUNCNAME,RET, ERRCLASS) do { \
    if (!g_module_symbol ((MODULE), (FUNCNAME), (gpointer *)&(RET))) \
    { \
        g_set_error (&tmp_error, KEYAGENT_ERROR, (ERRCLASS), \
                   "%s", g_module_error ()); \
        goto errexit; \
    } \
} while (0)

using namespace restbed;

extern void keytransfer_authentication_handler( const shared_ptr< Session > session, const function< void ( const shared_ptr< Session > ) >& callback );
extern void get_keytransfer_method_handler( const shared_ptr< Session > session );
extern void get_kms_keytransfer_method_handler( const shared_ptr< Session > session );
extern void keysession_authentication_handler( const shared_ptr< Session > session, const function< void ( const shared_ptr< Session > ) >& callback );
extern void get_keysession_method_handler( const shared_ptr< Session > session );
extern void get_kms_keysession_method_handler( const shared_ptr< Session > session );
extern void get_kms_key_usagepolices_method_handler( const shared_ptr< Session > session );
extern void print_input_headers(const char *label, const shared_ptr< Session > session);


namespace server {
    GHashTable *key_hash_table;
    GHashTable *session_hash_table;
    //GHashTable *client_session_hash_table;
    GHashTable *client_hash_table;
    GHashTable *session_to_stm_hash_table;
    GHashTable *key_type_hash;
    GHashTable *rsa_padtype_hash;
    GHashTable *swk_type_hash;
	const char *swk_type_str;
	keyagent_keytype keytype;
	gint rsa_padtype;

    gboolean debug;
    gboolean use_cms;
    gboolean verbose;
    gchar *configfile;
    GString *configdirectory;
    keyagent_module *stm;
    gchar *certfile;
    X509 *cert;
    EVP_PKEY *cert_key;
	gboolean generate_cert_with_key;
	GString *cert_key_path;
	GString *stm_filename;

    gchar *dhparam;
    gchar *cert_pool;
    gint port;
    gboolean tls_auth_support;
    GString *abs_cert_path;
    GString *abs_dhparam_path;
    GString *abs_cert_pool_path;
}

/*static const char *supported_swk_types[] = {"AES192-CTR", "AES256-CTR", "AES128-GCM", "AES192-GCM", "AES256-GCM", "AES128-CBC", */
/*"AES192-CBC", "AES256-CBC","AES128-XTS", "AES256-XTS", NULL};*/
static const char *supported_swk_types[] = { 
	"AES128-GCM", "AES192-GCM", "AES256-GCM",
    "AES128-CBC","AES192-CBC", "AES256-CBC",
    "AES128-WRAP","AES192-WRAP", "AES256-WRAP",
    NULL};

swk_type_op swk_type_fns[]={
	{128,  EVP_aes_128_gcm, aes_gcm_encrypt, NULL},
	{192,  EVP_aes_192_gcm, aes_gcm_encrypt, NULL},
	{256,  EVP_aes_256_gcm, aes_gcm_encrypt, NULL},
	{128,  EVP_aes_128_cbc, aes_cbc_encrypt, NULL},
	{192,  EVP_aes_192_cbc, aes_cbc_encrypt, NULL},
	{256,  EVP_aes_256_cbc, aes_cbc_encrypt, NULL},
	{128,  EVP_aes_128_wrap, aes_wrap_encrypt, NULL},
	{192,  EVP_aes_192_wrap, aes_wrap_encrypt, NULL},
	{256,  EVP_aes_256_wrap, aes_wrap_encrypt, NULL},
};

void
print_input_headers(const char *label, const shared_ptr< Session > session)
{
    for ( const auto header : session->get_request()->get_headers( ) )
        k_debug_msg("%s Header '%s' > '%s'\n", (label ? label : ""), header.first.data( ), header.second.data( ) );
}

extern "C" gboolean
server_hash_init(GError **error)
{
    const char **ptr;
    swk_type_op *opptr;
    server::swk_type_hash = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, NULL);
    for (ptr = supported_swk_types, opptr = swk_type_fns; *ptr; ++ptr, ++opptr) {
		GQuark q = g_quark_from_string(*ptr);
        g_hash_table_insert(server::swk_type_hash, GUINT_TO_POINTER(q), (gpointer)opptr);
    } 
    server::key_type_hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);
    g_hash_table_insert(server::key_type_hash, (gpointer)"RSA", GUINT_TO_POINTER(KEYAGENT_RSAKEY));
    g_hash_table_insert(server::key_type_hash, (gpointer)"EC", GUINT_TO_POINTER(KEYAGENT_ECKEY));
    g_hash_table_insert(server::key_type_hash, (gpointer)"AES", GUINT_TO_POINTER(KEYAGENT_AESKEY));

    server::rsa_padtype_hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);
    g_hash_table_insert(server::rsa_padtype_hash, (gpointer)"PKCS1", GUINT_TO_POINTER(RSA_PKCS1_PADDING));
    g_hash_table_insert(server::rsa_padtype_hash, (gpointer)"PKCS1_OAEP", GUINT_TO_POINTER(RSA_PKCS1_OAEP_PADDING));
    return TRUE;
}

void service_authentication_handler( const shared_ptr< Session > session, const function< void ( const shared_ptr< Session > ) >& callback )
{
    auto authorisation = session->get_request( )->get_header( "Authorization" );
    {
        callback( session );
    }
}

class CustomLogger : public Logger
{
    public:
        void stop( void )
        {
            return;
        }

        void start( const shared_ptr< const Settings >& )
        {
            return;
        }

        void log( const Level, const char* format, ... )
        {
            va_list arguments;
            va_start( arguments, format );
            
            vfprintf( stderr, format, arguments );
            fprintf( stderr, "\n" );
            
            va_end( arguments );
        }

        void log_if( bool expression, const Level level, const char* format, ... )
        {
            if ( expression )
            {
                va_list arguments;
                va_start( arguments, format );
                log( level, format, arguments );
                va_end( arguments );
            }
        }
};

keyagent_stm_real *
server_initialize_stm(const char *filename, GError **err )
{
    keyagent_stm_real *stm = g_new0(keyagent_stm_real, 1);
    stm->module_name = g_string_new(filename);
    const char *name = NULL;


    g_autoptr(GError) tmp_error = NULL;

    stm->module = g_module_open (stm->module_name->str, G_MODULE_BIND_LAZY);
    if (!stm->module)
    {
        g_set_error (&tmp_error, KEYAGENT_ERROR, KEYAGENT_ERROR_STMLOAD,
                     "%s", g_module_error ());
        goto errexit;
    }
    LOOKUP_STM_INTERFACES(stm, KEYAGENT_ERROR_STMLOAD);

    name = STM_MODULE_OP(stm,init)(server::configdirectory->str, KEYSERVER_STM_MODE, &tmp_error);
    if (!name) {
        k_info_error(tmp_error);
        goto errexit;
    }
    keyagent_set_module_label(stm, name);

    stm->initialized = 1;
    //g_hash_table_insert(keyagent::stm_hash, keyagent_get_module_label(stm), stm);
    //keyagent_stm_set_session((keyagent_module *)stm, NULL);
    return stm;
    errexit:
    if (stm->module)
    {
        if (!g_module_close (stm->module))
            g_warning ("%s: %s", filename, g_module_error ());
    }
    stm->module = NULL;
    g_free(stm);
    //g_propagate_error (err, tmp_error);
    k_info_msg ("Error loading stm - %s: %s", filename, tmp_error->message);
    return NULL;
}

gboolean
initialize_certificate()
{
    BIO *cert = NULL;
    gboolean ret = FALSE;

    if ((cert = BIO_new(BIO_s_file())) == NULL) {
        goto out;
    }

    if (BIO_read_filename(cert, server::certfile) <= 0) {
        k_critical_msg("Error opening certificate file - %s\n", server::certfile);
        goto out;
    }

    server::cert = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
    if (!server::cert) {
        k_critical_msg("Error opening certificate file - %s\n", server::certfile);
        goto out;
    }
    BIO_free(cert);
    if ((cert = BIO_new(BIO_s_file())) == NULL) {
        goto out;
    }
    if (BIO_read_filename(cert, server::certfile) <= 0) {
        k_critical_msg("Error opening certificate file - %s\n", server::certfile);
        goto out;
    }
    server::cert_key = PEM_read_bio_PrivateKey(cert, NULL, NULL, NULL);
    if (!server::cert_key) {
        k_critical_msg("Error opening certificate file - %s\n", server::certfile);
        goto out;
    }
    ret = TRUE;
out:
    if (cert)
        BIO_free(cert);
    return ret;
}

static GOptionEntry entries[] =
        {
                { "verbose", 'v', 0, G_OPTION_ARG_NONE, &server::verbose, "Be verbose", NULL },
                { "config", 0, 0, G_OPTION_ARG_FILENAME, &server::configfile, "required! config file to use", NULL },
                { "cert", 0, 0, G_OPTION_ARG_FILENAME, &server::certfile, "required! cert file to use", NULL },
                { "dhparam", 0, 0, G_OPTION_ARG_FILENAME, &server::dhparam, "required! difie helman file to use", NULL },
                { "cert_pool", 0, 0, G_OPTION_ARG_FILENAME, &server::cert_pool, "required! cert pool path to use", NULL },
                { "debug", 0, 0, G_OPTION_ARG_NONE, &server::debug, "enable debug output", NULL },
                { NULL }
        };


KEYAGENT_DEFINE_ATTRIBUTES()


void free_server_namespace()
{
	if( server::configdirectory )
		g_string_free(server::configdirectory, TRUE);
	if( server::cert_key_path )
		g_string_free(server::cert_key_path, TRUE);
	if( server::stm_filename )
		g_string_free(server::stm_filename, TRUE);
    if( server::abs_cert_path )
        g_string_free(server::abs_cert_path, TRUE);
    if( server::abs_dhparam_path )
        g_string_free(server::abs_dhparam_path, TRUE);
    if( server::abs_cert_pool_path )
        g_string_free(server::abs_cert_pool_path,  TRUE);
}

int main(int argc, char** argv)
{
    GOptionContext *context;
    GError *err = NULL;
	gint ret=EXIT_FAILURE;
	void *config=NULL;


    Service service;
    auto keytransfer = make_shared< Resource >( );
	auto kmskeytransfer = make_shared< Resource >( );
    auto keysession = make_shared< Resource >( );
    auto kmskeysession = make_shared< Resource >( );
    auto kms_key_usagepolices= make_shared< Resource >( );
    auto settings = make_shared< Settings >( );
    auto ssl_settings = make_shared< SSLSettings >( );

    server::key_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, key_info_free);
    server::session_hash_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, session_hash_value_free);
    server::session_to_stm_hash_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    server::client_hash_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, client_hash_value_free);

    server::debug = FALSE;
    server::abs_cert_path = g_string_new("file://");
    server::abs_dhparam_path = g_string_new("file://");
    server::abs_cert_pool_path = g_string_new("file://");

    context = g_option_context_new ("- key-agent cli");
    g_option_context_add_main_entries (context, entries, NULL);
    if (!g_option_context_parse (context, &argc, &argv, &err))
    {
        g_print ("option parsing failed: %s\n", err->message);
		goto out;
	}

    if (!server::configfile)
		server::configfile = g_strconcat (DHSM2_CONF_PATH,"/testserver.ini", NULL);

    if (!server::certfile)
        server::certfile = g_strconcat (DHSM2_INSTALL_DIR,"/store/testserver/ssl/server/server_certificate.pem", NULL);

    if (!server::dhparam)
        server::dhparam = g_strconcat (DHSM2_INSTALL_DIR,"/store/testserver/ssl/client/dhparam.pem", NULL);

    if (!server::cert_pool)
        server::cert_pool = g_strconcat (DHSM2_INSTALL_DIR,"/store/testserver/ssl/CA", NULL);

    g_string_append(server::abs_cert_path, realpath(server::certfile, NULL));
    g_string_append(server::abs_dhparam_path, realpath(server::dhparam, NULL));
    g_string_append(server::abs_cert_pool_path, realpath(server::cert_pool, NULL));

    if (server::debug)
        setenv("G_MESSAGES_DEBUG", "all", 1);


    server::configdirectory = g_string_new(g_path_get_dirname(server::configfile));

	config = key_config_openfile(server::configfile, &err);
    server::stm_filename = g_string_new(key_config_get_string(config, "core", "STM", &err));
    if (err != NULL) {
        k_fatal_error(err);
		goto out;
    }
    server::stm = (keyagent_module *)server_initialize_stm(server::stm_filename->str, &err);
    if (!server::stm)
	{
        k_fatal_error(err);
		goto out;
	}

   	server::use_cms = key_config_get_boolean_optional(config, "core", "use_cms", TRUE); 

    server::tls_auth_support = key_config_get_boolean_optional(config, "core", "tls_auth_support", FALSE);
    k_info_msg("TLS Auth support:%d", server::tls_auth_support);

    if (server::tls_auth_support)
        server::port = 443;
    else
        server::port = 1984;

   	server::port = key_config_get_integer_optional(config, "core", "port", server::port); 

	server_hash_init(&err);

    if (err != NULL) {
        k_fatal_error(err);
		goto out;
	}
    k_info_msg("Using stm %s", keyagent_get_module_label(server::stm));

	{
    	char *swk_type = key_config_get_string(config, keyagent_get_module_label(server::stm), "swk_type", &err); 
    	if (err != NULL) {
        	k_fatal_error(err);
			goto out;
    	}
		k_debug_msg("swk_type %s", swk_type);
		if (!get_swk_info(swk_type)) {
			k_fatal_msg("Invalid swk_type (%s) set for %s", swk_type, keyagent_get_module_label(server::stm));
			goto out;
		}
		server::swk_type_str = swk_type;

    	char *keytype = key_config_get_string(config, keyagent_get_module_label(server::stm), "keytype", &err); 
    	if (err != NULL) {
        	k_fatal_error(err);
			goto out;
    	}
		k_debug_msg("keytype %s", keytype);
		server::keytype = (keyagent_keytype)GPOINTER_TO_UINT(g_hash_table_lookup(server::key_type_hash, (gpointer)keytype));
		if (!server::keytype) {
			k_fatal_msg("Invalid key type (%s) set for %s", keytype, keyagent_get_module_label(server::stm));
			goto out;
		}

		if (server::keytype == KEYAGENT_RSAKEY) {
    		server::generate_cert_with_key = key_config_get_boolean_optional(config, "core", "generate_certificate_with_key", FALSE); 
   			k_info_msg("Nginx Support:%d", server::generate_cert_with_key);
		} else {
    		server::generate_cert_with_key = FALSE;
   			k_info_msg("Nginx Support: Disabling, not generating RSA key");
		}

    	char *rsa_padtype = key_config_get_string(config, keyagent_get_module_label(server::stm), "rsapad", &err); 
    	if (err != NULL) {
        	k_fatal_error(err);
			goto out;
    	}
		k_debug_msg("rsapad %s", rsa_padtype);
		server::rsa_padtype = (gint)GPOINTER_TO_UINT(g_hash_table_lookup(server::rsa_padtype_hash, (gpointer)rsa_padtype));
		if (!server::rsa_padtype) {
			k_fatal_msg("Invalid rsa pad type (%s) set for %s", rsa_padtype, keyagent_get_module_label(server::stm));
			goto out;
		}
	}


	if( server::generate_cert_with_key == TRUE)
	{
		server::cert_key_path = g_string_new(key_config_get_string_optional(config, "core", "key_cert_path", DHSM2_INSTALL_DIR));
        g_string_append(server::cert_key_path, "/store/testserver/ssl/client");

        k_info_msg("Creating cert folder:%s", server::cert_key_path->str);
		g_mkdir_with_parents((const gchar *)server::cert_key_path->str, 755);
	}

    if ( initialize_certificate() != TRUE )
	{
        k_critical_msg("Invalid certificate information\n");
		goto out;
		//exit (1);
	}

    keytransfer->set_path( "/keys/transfer" );
    keytransfer->set_method_handler( "GET", get_keytransfer_method_handler );
    keytransfer->set_authentication_handler( keytransfer_authentication_handler );

    kmskeytransfer->set_path(  "v1/keys/.*/dhsm2-transfer");
    kmskeytransfer->set_method_handler( "GET", get_kms_keytransfer_method_handler );
    kmskeytransfer->set_authentication_handler( keytransfer_authentication_handler );

    keysession->set_path( "/keys/session" );
    keysession->set_method_handler( "POST", get_keysession_method_handler );
    keysession->set_authentication_handler( keysession_authentication_handler );
    
    kmskeysession->set_path( "v1/kms/keys/session" );
    kmskeysession->set_method_handler( "POST", get_kms_keysession_method_handler );
    kmskeysession->set_authentication_handler( keysession_authentication_handler );
    
    kms_key_usagepolices->set_path( "v1/key-usage-policies/.*" );
    kms_key_usagepolices->set_method_handler( "GET", get_kms_key_usagepolices_method_handler );
    kms_key_usagepolices->set_authentication_handler( keysession_authentication_handler );

    if( server::tls_auth_support == TRUE)
    {
        ssl_settings->set_port(server::port );
        ssl_settings->set_http_disabled( true );
        ssl_settings->set_client_authentication_enabled( true );

        ssl_settings->set_private_key( Uri( server::abs_cert_path->str ) );
        ssl_settings->set_certificate( Uri( server::abs_cert_path->str ) );
        ssl_settings->set_temporary_diffie_hellman( Uri( server::abs_dhparam_path->str ) );
        ssl_settings->set_certificate_authority_pool( Uri( server::abs_cert_pool_path->str ) );

        settings->set_default_header( "Connection", "close" );
        settings->set_ssl_settings( ssl_settings );
    }else{
        settings->set_port(server::port );
        settings->set_default_header( "Connection", "close" );
    }

    service.publish( keytransfer );
    service.publish( kmskeytransfer );
    service.publish( keysession );
    service.publish( kmskeysession );
    service.publish( kms_key_usagepolices );
    service.set_authentication_handler( service_authentication_handler );
    
    service.set_logger( make_shared< CustomLogger >( ) );

	//generate_key();
    service.start( settings );
	ret =  EXIT_SUCCESS;

out:
    free_server_namespace();
    return ret;
}
