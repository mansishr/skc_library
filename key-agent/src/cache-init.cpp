
#include "key-agent/key_agent.h"
#include "key-agent/types.h"
#include "config-file/key_configfile.h"

#include "internal.h"
#include <errno.h>
#include "k_errors.h"
#include <libgda/libgda.h>
#include <libgda/gda-blob-op.h>
#include <sql-parser/gda-sql-parser.h>

namespace keyagent {
    namespace localcache {
        GString *provider_name;
        GString *database_name;
        GString *full_database_name;
        GString *database_directory;
        GString *connection_string;
        gpointer connection_pointer;
        gboolean cache_sessions;
        gboolean cache_keys;
        volatile gint fake_cache_ids;
        GRWLock cache_rwlock;
    }
}

extern "C" gint
keyagent_cache_generate_fake_id()
{
    g_atomic_int_add(&keyagent::localcache::fake_cache_ids, 1);
}

static gboolean
open_cache_connection(GError **error)
{
    GdaConnection *cnc;
    GdaSqlParser *parser;

    /* open connection */
    keyagent::localcache::connection_pointer = (gpointer) gda_connection_open_from_string (keyagent::localcache::provider_name->str,
                                           keyagent::localcache::connection_string->str,
                                           NULL, GDA_CONNECTION_OPTIONS_NONE, error);
    if (!keyagent::localcache::connection_pointer) {
        k_critical_msg("Could not open connection to the %s database at %s: %s\n",
                    keyagent::localcache::provider_name->str,
                    keyagent::localcache::full_database_name->str,
                    *error && (*error)->message ? (*error)->message : "No detail");
        return FALSE;
    }
    /* create an SQL parser */
    parser = gda_connection_create_parser (GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer));
    if (!parser)
        parser = gda_sql_parser_new ();
    /* attach the parser object to the connection */
    g_object_set_data_full (G_OBJECT (GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer)), "parser", parser, g_object_unref);
    return TRUE;
}

static gboolean
run_sql_non_select (const gchar *sql, GError **error)
{
    GdaStatement *stmt;
    gint nrows;
    const gchar *remain;
    GdaSqlParser *parser;

    parser = (GdaSqlParser *)g_object_get_data (G_OBJECT (GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer)), "parser");
    stmt = gda_sql_parser_parse_string (parser, sql, &remain, error);
    if (!stmt)
        return FALSE;
    //if (remain) g_print ("REMAINS: %s\n", remain);

    nrows = gda_connection_statement_execute_non_select (GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), stmt, NULL, NULL, NULL);
    g_object_unref (stmt);
    return TRUE;
}


static gboolean
create_cache_tables(GError **error)
{
    gboolean ret = FALSE;
    if (!run_sql_non_select ("CREATE TABLE keys (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, sealed_data BLOB NOT NULL, session_id VARCHAR(64) NOT NULL, key_type INTEGER NOT NULL, url VARCHAR (256) NOT NULL UNIQUE ON CONFLICT REPLACE)", error))
        goto out;
    if (!run_sql_non_select ("CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, stm_label VARCHAR (64) NOT NULL UNIQUE ON CONFLICT REPLACE, swk BLOB NOT NULL, session_id VARCHAR (64), swk_type VARCHAR (64))", error))
        goto out;
    if (!run_sql_non_select ("CREATE TABLE key_attributes (keyattr_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, key_id INTEGER NOT NULL REFERENCES keys (id) ON UPDATE CASCADE, attr_name VARCHAR(64) NOT NULL, attr_value BLOB NOT NULL, UNIQUE (key_id, attr_name) ON CONFLICT REPLACE)", error)) {
        k_critical_error(*error);
        goto out;
    }
    gda_connection_commit_transaction(GPOINTER_TO_GDA_CONNECTION(keyagent::localcache::connection_pointer), NULL, NULL);
    ret = TRUE;
    out:
    return ret;
}

extern "C" gboolean
keyagent_cache_init(GError **err)
{
    GString *tmp = g_string_new(NULL);
    g_string_append_printf(tmp, PKGDATA "/var/cache/keyagent_cache");

    keyagent::localcache::cache_sessions = key_config_get_boolean_optional(keyagent::config, "cache", "cache_sessions", TRUE);
    keyagent::localcache::cache_keys = key_config_get_boolean_optional(keyagent::config, "cache", "cache_keys", FALSE);
    g_rw_lock_init (&keyagent::localcache::cache_rwlock);

    if (!keyagent::localcache::cache_sessions && !keyagent::localcache::cache_keys)
        return TRUE;

    keyagent::localcache::provider_name = g_string_new(key_config_get_string_optional(keyagent::config, "cache", "database_provider", "SQLite"));
    keyagent::localcache::full_database_name = g_string_new(key_config_get_string_optional(keyagent::config, "cache", "database_name", tmp->str));
    keyagent::localcache::database_directory = g_string_new(g_path_get_dirname(keyagent::localcache::full_database_name->str));;
    keyagent::localcache::database_name = g_string_new(g_path_get_basename(keyagent::localcache::full_database_name->str));;


    keyagent::localcache::connection_string = g_string_new(NULL);
    g_string_append_printf(keyagent::localcache::connection_string, "DB_DIR=%s;DB_NAME=%s",
            keyagent::localcache::database_directory->str,
            keyagent::localcache::database_name->str);

    if (g_mkdir_with_parents(keyagent::localcache::database_directory->str, 0700)) {
        g_set_error (err, G_FILE_ERROR,
                     g_file_error_from_errno (errno),
                     "Error making directory '%s': %s",
                     keyagent::localcache::database_directory->str,
                     g_strerror (errno));

        return FALSE;
    }
    if (!open_cache_connection(err))
        return FALSE;

    if (!create_cache_tables(err))
        return FALSE;

    if (keyagent::localcache::cache_sessions && !keyagent_cache_loadsessions(err))
        return FALSE;

    if (keyagent::localcache::cache_keys && !keyagent_cache_loadkeys(err))
        return FALSE;

    return TRUE;
}
