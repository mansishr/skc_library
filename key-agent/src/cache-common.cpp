#include "key-agent/key_agent.h"
#include "key-agent/types.h"
#include "internal"
#include <errno.h>
#include "k_errors.h"



extern "C" gboolean
issue_insert(GdaConnection *cnc, GdaStatement *stmt, GdaSet *params, gint *last_id, GError **error)
{
    GdaSet *last_row;

    gint rows = gda_connection_statement_execute_non_select(cnc, stmt, params, &last_row, error);
    g_object_unref(params);
    g_object_unref(stmt);

    if ((rows == -1) && !last_row) {
        k_info_error(*error);
        return FALSE;
    }
    GSList *list = last_row->holders;
    GdaHolder *h = GDA_HOLDER(list->data);
    const GValue *value = gda_holder_get_value(h);
    *last_id = g_value_get_int(value);
    g_object_unref(last_row);

    return TRUE;
}
