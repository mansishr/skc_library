#define G_LOG_DOMAIN "keyagent-request"

#include "internal.h"
#include "k_errors.h"

typedef struct {
	guint8 bytes[16];
}_uuid;

static gchar *
uuid_to_string(const _uuid *uuid)
{
	const guint8 *bytes;
	bytes = uuid->bytes;
	return g_strdup_printf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x"
		"-%02x%02x%02x%02x%02x%02x",
		bytes[0], bytes[1], bytes[2], bytes[3],
		bytes[4], bytes[5], bytes[6], bytes[7],
		bytes[8], bytes[9], bytes[10], bytes[11],
		bytes[12], bytes[13], bytes[14], bytes[15]);
}

static void
uuid_set_version(_uuid *uuid, guint version)
{
	guint8 *bytes = uuid->bytes;
	/*
	 * Set the four most significant bits (bits 12 through 15) of the
	 * time_hi_and_version field to the 4-bit version number from
	 * Section 4.1.3.
	*/
	bytes[6] &= 0x0f;
	bytes[6] |= version << 4;
	/*
	 * Set the two most significant bits (bits 6 and 7) of the
	 * clock_seq_hi_and_reserved to zero and one, respectively.
	*/
	bytes[8] &= 0x3f;
	bytes[8] |= 0x80;
}

static void
uuid_generate_v4(_uuid *uuid)
{
	int i;
	guint8 *bytes;
	guint32 *ints;
	bytes = uuid->bytes;
	ints = (guint32 *) bytes;
	for(i = 0; i < 4; i++)
		ints[i] = g_random_int ();

	uuid_set_version(uuid, 4);
}

const char *
keyagent_generate_request_id()
{
	_uuid uuid;
	uuid_generate_v4(&uuid);
	return uuid_to_string(&uuid);
}

void DLL_LOCAL
keyagent_request_id_destory(gpointer data)
{
	g_free(data);
}
