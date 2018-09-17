#define G_LOG_DOMAIN "keyagent-errors"

#include <glib.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdio.h>
#include "key-agent/key_agent.h"
#include "k_errors.h"

#include <string.h>

const char *programname;
GString *testdir = NULL;

typedef struct {
    const GLogField *fields;
    gsize n_fields;
} ExpectedMessage;

gboolean
test_fields(const GLogField *f1, const GLogField *f2) {
    char *value = (char *) f1->value;

    if (strcmp(f1->key, f2->key) != 0)
        return FALSE;

    // Our error macros add FILE(LINENUMBER): to front of message that we need to skip
    if (strcmp(f1->key, "MESSAGE") == 0) {
        value = strstr(value, ":");
        if (value)
            value += 2;
        else
            value = (char *) f1->value;
    }

    if (f1->length != f2->length)
        return FALSE;

    if (f1->length == -1)
        return strcmp(value, f2->value) == 0;
    else
        return memcmp(value, f2->value, strlen(value)) == 0;
}

static gboolean
compare_fields(const GLogField *f1, gsize n1, const GLogField *f2, gsize n2) {
    int i, j;

    for (i = 0; i < n1; i++) {
        for (j = 0; j < n2; j++) {
            if (test_fields(&f1[i], &f2[j]))
                break;
        }
        if (j == n2)
            return FALSE;
    }

    return TRUE;
}

gboolean set_testdir(const gchar *option_name,
                     const gchar *value,
                     gpointer data,
                     GError **error) {
    testdir = g_string_new(value);
    testdir = g_string_append(testdir, "/");
}

static void
test_fatal_msg(void) {
    g_autoptr(GError)
    error = NULL;
    k_set_error(&error, 5, "foo is it %d", 77);
    if (g_test_subprocess()) {
        k_fatal_error(error);
        return;
    }

    // Reruns this same test in a subprocess
    g_test_trap_subprocess(NULL, 0, 0);
    g_test_trap_assert_failed();
}

static GSList *expected_messages = NULL;

static GLogWriterOutput
expect_log_writer(GLogLevelFlags log_level,
                  const GLogField *fields,
                  gsize n_fields,
                  gpointer user_data) {
    ExpectedMessage *expected = expected_messages->data;

    if (compare_fields(fields, n_fields, expected->fields, expected->n_fields)) {
        expected_messages = g_slist_delete_link(expected_messages, expected_messages);
    } else if ((log_level & G_LOG_LEVEL_DEBUG) != G_LOG_LEVEL_DEBUG)
    {
        char *str;
        str = g_log_writer_format_fields(log_level, fields, n_fields, FALSE);
        g_test_message ("Unexpected message: %s", str);
        g_free(str);
        g_test_fail();
    }

    return G_LOG_WRITER_HANDLED;
}


static const gchar *
log_level_to_priority(GLogLevelFlags log_level) {
    if (log_level & G_LOG_LEVEL_ERROR)
        return "3";
    else if (log_level & G_LOG_LEVEL_CRITICAL)
        return "4";
    else if (log_level & G_LOG_LEVEL_WARNING)
        return "4";
    else if (log_level & G_LOG_LEVEL_MESSAGE)
        return "5";
    else if (log_level & G_LOG_LEVEL_INFO)
        return "6";
    else if (log_level & G_LOG_LEVEL_DEBUG)
        return "7";

    /* Default to LOG_NOTICE for custom log levels. */
    return "5";
}


static void
test_logging_errors(gconstpointer test_data) {
    ulong log_level = (ulong) GPOINTER_TO_INT(test_data);

    const GLogField fields[] = {
            {"GLIB_DOMAIN", G_LOG_DOMAIN,                                                     -1},
            {"PRIORITY", log_level_to_priority(log_level),                                    -1},
            {"MESSAGE",  "Failed to open file: Interrupted system call: (keyagent-errors,4)", -1},
    };
    ExpectedMessage expected = {fields, 3};

    expected_messages = g_slist_append(NULL, &expected);
    g_log_set_writer_func(expect_log_writer, NULL, NULL);

    g_autoptr(GError)
    error = NULL;
    k_set_domain_error(&error, K_LOG_DOMAIN_ERROR, 4, "Failed to open file: %s", g_strerror(4));

    switch (log_level) {
        case G_LOG_LEVEL_CRITICAL:
            k_critical_error(error);
            break;
        case G_LOG_LEVEL_WARNING:
            k_info_error(error);
            break;
        case G_LOG_LEVEL_DEBUG:
            k_debug_error(error);
            break;
    }
    g_assert(expected_messages == NULL);
}

static void
test_logging_msg(gconstpointer test_data) {
    ulong log_level = (ulong) GPOINTER_TO_INT(test_data);

    const GLogField fields[] = {
            {"GLIB_DOMAIN", G_LOG_DOMAIN,                  -1},
            {"PRIORITY", log_level_to_priority(log_level), -1},
            {"MESSAGE",  "This is a test",                 -1},
    };
    ExpectedMessage expected = {fields, 3};

    expected_messages = g_slist_append(NULL, &expected);
    g_log_set_writer_func(expect_log_writer, NULL, NULL);

    switch (log_level) {
        case G_LOG_LEVEL_CRITICAL:
            k_critical_msg("This is a test");
            break;
        case G_LOG_LEVEL_WARNING:
            k_info_msg("This is a test");
            break;
        case G_LOG_LEVEL_DEBUG:
            k_debug_msg("This is a test");
            break;
    }
    g_assert(expected_messages == NULL);
}


static GOptionEntry entries[] =
        {
                {"testdir", 'D', 0, G_OPTION_ARG_CALLBACK, set_testdir, "Directory where test files are", NULL},
                {NULL}
        };

int main(int argc, char **argv)
{

    GOptionContext *context;
    GError *error = NULL;
    context = g_option_context_new ("- test keyagent");

    programname = argv[0];

    g_test_init(&argc, &argv, NULL, "no_g_set_prgname", NULL);

    g_option_context_add_main_entries (context, entries, "keyagent");
    if (!g_option_context_parse (context, &argc, &argv, &error))
    {
        g_print ("option parsing failed: %s\n", error->message);
        exit (1);
    }

	if (!testdir) {
        char *tmp = dirname(strdup(programname));
        char *tmp1 = basename(strdup(tmp));
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s", tmp); //dirname((char *)programname));
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s", tmp1); //dirname((char *)programname));
        if (!strcmp(basename(tmp), ".libs"))
            tmp = dirname(tmp);
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s", tmp); //dirname((char *)programname));
        
		//g_log_structured(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, "MESSAGE", "%s", tmp); //dirname((char *)programname));
		set_testdir(NULL,tmp, NULL, NULL);
	}

    g_test_add_func("/logging/messages/fatal", test_fatal_msg);
    g_test_add_data_func("/logging/errors/critical", GINT_TO_POINTER(G_LOG_LEVEL_CRITICAL), test_logging_errors);
    g_test_add_data_func("/logging/errors/info", GINT_TO_POINTER(G_LOG_LEVEL_WARNING), test_logging_errors);
    g_test_add_data_func("/logging/errors/debug", GINT_TO_POINTER(G_LOG_LEVEL_DEBUG), test_logging_errors);
    g_test_add_data_func("/logging/messages/critical", GINT_TO_POINTER(G_LOG_LEVEL_CRITICAL), test_logging_msg);
    g_test_add_data_func("/logging/messages/info", GINT_TO_POINTER(G_LOG_LEVEL_WARNING), test_logging_msg);
    g_test_add_data_func("/logging/messages/debug", GINT_TO_POINTER(G_LOG_LEVEL_DEBUG), test_logging_msg);

    return g_test_run();
}
