#include <memory>
#include <cstdlib>
#include <ciso646>
#include <functional>
#include <restbed>
#include "keyserver.h"
#include <glib.h>
#include "config-file/key_configfile.h"
#include "k_errors.h"
#include "key-agent/types.h"
#include "key-agent/src/internal.h"
#include "config.h"

namespace server {
    GHashTable *key_hash_table;
    GHashTable *session_hash_table;
    //GHashTable *client_session_hash_table;
    GHashTable *client_hash_table;
    GHashTable *session_to_stm_hash_table;
    GHashTable *swk_type_hash;

    gboolean debug;
    gboolean verbose;
    gchar *configfile;
    GString *configdirectory;
    keyagent_module *stm;
    gchar *certfile;
    X509 *cert;
    EVP_PKEY *cert_key;
}


swk_type_op swk_type_fns[]={
	{128,  EVP_aes_128_gcm, aes_gcm_encrypt, NULL},
	{192,  EVP_aes_192_gcm, aes_gcm_encrypt, NULL},
	{256,  EVP_aes_256_gcm, aes_gcm_encrypt, NULL},
	{128,  EVP_aes_128_cbc, aes_cbc_encrypt, NULL},
	{192,  EVP_aes_192_cbc, aes_cbc_encrypt, NULL},
	{256,  EVP_aes_256_cbc, aes_cbc_encrypt, NULL},
};
extern "C" gboolean
server_swk_hash_init(GError **error)
{
    const char **ptr;
    swk_type_op *opptr;
    server::swk_type_hash = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, NULL);
    for (ptr = supported_swk_types, opptr = swk_type_fns; *ptr; ++ptr, ++opptr) {
		GQuark q = g_quark_from_string(*ptr);
        g_hash_table_insert(server::swk_type_hash, GUINT_TO_POINTER(q), (gpointer)opptr);
    } 
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
                { "debug", 0, 0, G_OPTION_ARG_NONE, &server::debug, "enable debug output", NULL },
                { NULL }
        };


KEYAGENT_DEFINE_ATTRIBUTES()



int main(int argc, char** argv)
{
    GOptionContext *context;
    GError *err = NULL;

    server::key_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, key_info_free);
    //server::client_session_hash_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, client_session_hash_value_free);
    server::session_hash_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, session_hash_value_free);
    server::session_to_stm_hash_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    server::client_hash_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, client_hash_value_free);

    server::debug = FALSE;

    context = g_option_context_new ("- key-agent cli");
    g_option_context_add_main_entries (context, entries, NULL);
    if (!g_option_context_parse (context, &argc, &argv, &err))
    {
        g_print ("option parsing failed: %s\n", err->message);
        exit (1);
    }
    if (!server::configfile)
    {
		server::configfile = g_strconcat (DHSM2_CONF_PATH,"/testserver.ini", NULL);
	}

    if (!server::certfile)
    {
        g_print("%s\n", g_option_context_get_help (context, TRUE, NULL));
        exit(1);
    }
    if (server::debug) {
        setenv("G_MESSAGES_DEBUG", "all", 1);
    }


    server::configdirectory = g_string_new(g_path_get_dirname(server::configfile));

    GString *configfilename = g_string_new(server::configfile);
    void *config = key_config_openfile(server::configfile, &err);
    GString *stm_filename = g_string_new(key_config_get_string(config, "core", "STM", &err));
    if (err != NULL) {
        k_fatal_error(err);
    }

    if ( initialize_certificate() != TRUE )
	{
        k_critical_msg("Invalid certificate information\n");
	    exit (1);
	}

    server::stm = (keyagent_module *)server_initialize_stm(stm_filename->str, &err);
    if (!server::stm)
        k_fatal_error(err);

	server_swk_hash_init(&err);
    if (err != NULL) {
        k_fatal_error(err);
	}
    k_info_msg("Using stm %s", keyagent_get_module_label(server::stm));


    auto keytransfer = make_shared< Resource >( );
    keytransfer->set_path( "/keys/transfer" );
    keytransfer->set_method_handler( "GET", get_keytransfer_method_handler );
    keytransfer->set_authentication_handler( keytransfer_authentication_handler );

	auto kmskeytransfer = make_shared< Resource >( );
    kmskeytransfer->set_path(  "/keys/.*/transfer");
    kmskeytransfer->set_method_handler( "GET", get_kms_keytransfer_method_handler );
    kmskeytransfer->set_authentication_handler( keytransfer_authentication_handler );

    auto keysession = make_shared< Resource >( );
    keysession->set_path( "/keys/session" );
    keysession->set_method_handler( "POST", get_keysession_method_handler );
    keysession->set_authentication_handler( keysession_authentication_handler );
    
    auto kmskeysession = make_shared< Resource >( );
    kmskeysession->set_path( "v1/kms/keys/session" );
    kmskeysession->set_method_handler( "POST", get_kms_keysession_method_handler );
    kmskeysession->set_authentication_handler( keysession_authentication_handler );
    
    auto kms_key_usagepolices= make_shared< Resource >( );
    kms_key_usagepolices->set_path( "v1/key-usage-policies/.*" );
    kms_key_usagepolices->set_method_handler( "GET", get_kms_key_usagepolices_method_handler );
    kms_key_usagepolices->set_authentication_handler( keysession_authentication_handler );
    
    auto settings = make_shared< Settings >( );
    settings->set_port( 1984 );
    settings->set_default_header( "Connection", "close" );
    
    Service service;
    service.publish( keytransfer );
    service.publish( kmskeytransfer );
    service.publish( keysession );
    service.publish( kmskeysession );
    service.publish( kms_key_usagepolices );
    service.set_authentication_handler( service_authentication_handler );
    
    service.set_logger( make_shared< CustomLogger >( ) );

	//generate_key();
    service.start( settings );
    
    return EXIT_SUCCESS;
}
