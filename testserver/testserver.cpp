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

namespace server {
    GHashTable *uuid_hash_table;
    GHashTable *key_hash_table;
    gboolean debug;
    gboolean verbose;
    gchar *configfile;
    GString *configdirectory;
    //keyagent_real_stm *stm = NULL;
    keyagent_module *stm;
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

keyagent_real_stm *
server_initialize_stm(const char *filename, GError **err )
{
    keyagent_real_stm *stm = g_new0(keyagent_real_stm, 1);
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
    //KEYAGENT_MODULE_LOOKUP(stm->module, "stm_challenge_generate_request", stm->challange_generate_request_func, KEYAGENT_ERROR_STMLOAD);
    //KEYAGENT_MODULE_LOOKUP(stm->module, "stm_challenge_verify", stm->challenge_verify_func, KEYAGENT_ERROR_STMLOAD);


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


static GOptionEntry entries[] =
        {
                { "verbose", 'v', 0, G_OPTION_ARG_NONE, &server::verbose, "Be verbose", NULL },
                { "config", 0, 0, G_OPTION_ARG_FILENAME, &server::configfile, "required! config file to use", NULL },
                { "debug", 0, 0, G_OPTION_ARG_NONE, &server::debug, "enable debug output", NULL },
                { NULL }
        };


KEYAGENT_DEFINE_KEY_ATTRIBUTES()



int main(int argc, char** argv)
{
    GOptionContext *context;
    GError *err = NULL;

    server::uuid_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, challenge_info_free);
    server::key_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, key_info_free);
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
        g_print("%s\n", g_option_context_get_help (context, TRUE, NULL));
        exit(1);
    }
    if (server::debug) {
        setenv("G_MESSAGES_DEBUG", "all", 1);
    }


    k_debug_msg("iv %d %s", KEYAGENT_ATTR_IV, g_quark_to_string(KEYAGENT_ATTR_IV));
    k_debug_msg("rsad %d %s", KEYAGENT_ATTR_RSA_D, g_quark_to_string(KEYAGENT_ATTR_RSA_D));
    k_debug_msg("rsaP %d %s", KEYAGENT_ATTR_RSA_P, g_quark_to_string(KEYAGENT_ATTR_RSA_P));


    server::configdirectory = g_string_new(g_path_get_dirname(server::configfile));

    GString *configfilename = g_string_new(server::configfile);
    void *config = key_config_openfile(server::configfile, &err);
    GString *stm_filename = g_string_new(key_config_get_string(config, "core", "STM", &err));
    if (err != NULL) {
        k_fatal_error(err);
    }

    server::stm = (keyagent_module *)server_initialize_stm(stm_filename->str, &err);
    if (!server::stm)
        k_fatal_error(err);

    k_info_msg("Using stm %s", keyagent_get_module_label(server::stm));


    auto keytransfer = make_shared< Resource >( );
    keytransfer->set_path( "/keys/transfer" );
    keytransfer->set_method_handler( "GET", get_keytransfer_method_handler );
    keytransfer->set_authentication_handler( keytransfer_authentication_handler );

    auto keysession = make_shared< Resource >( );
    keysession->set_path( "/keys/session" );
    keysession->set_method_handler( "POST", get_keysession_method_handler );
    keysession->set_authentication_handler( keysession_authentication_handler );
    
    
    auto settings = make_shared< Settings >( );
    settings->set_port( 1984 );
    settings->set_default_header( "Connection", "close" );
    
    Service service;
    service.publish( keytransfer );
    service.publish( keysession );
    service.set_authentication_handler( service_authentication_handler );
    
    service.set_logger( make_shared< CustomLogger >( ) );

	//generate_key();
    service.start( settings );
    
    return EXIT_SUCCESS;
}
