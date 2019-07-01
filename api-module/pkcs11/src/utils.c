#define G_LOG_DOMAIN "pkcs11-util"

#include "internal.h"
#include <stdio.h>

static GString *
apimodule_utf8_to_char(CK_UTF8CHAR *utf8buf, size_t len)
{
	GString *buf = NULL;
    if (len <= 0) return NULL;

    while (len && utf8buf[len-1] == ' ')
        len--;

    if(len <= 0)
        return NULL;

	buf = g_string_new(NULL);
	k_debug_msg("%s:%d", utf8buf, len);
	if (buf) 
		buf = g_string_append_len(buf, utf8buf, len);

    return buf;
}

void
apimodule_uri_data_init(apimodule_uri_data *uri_data) 
{
    memset(uri_data,0, sizeof(apimodule_uri_data));
    uri_data->type = CKO_DATA;
}

void
apimodule_uri_data_cleanup(apimodule_uri_data *uri_data) 
{
    if (uri_data->token_label) g_string_free(uri_data->token_label, TRUE);
    if (uri_data->key_label) g_string_free(uri_data->key_label, TRUE);
    if (uri_data->key_id) g_string_free(uri_data->key_id, TRUE);
    if (uri_data->pin) g_string_free(uri_data->pin, TRUE);
    uri_data->type = -1;
    uri_data->slot_id = -1;
}

gboolean
apimodule_uri_to_uri_data(const char *uri, apimodule_uri_data *uri_data)
{
	gboolean ret = FALSE;
    P11KitUri *key_uri = NULL;
	CK_TOKEN_INFO_PTR tokenInfo = NULL;
	CK_ATTRIBUTE_PTR label_attr;
	CK_ATTRIBUTE_PTR id_attr;
	const char* upin;
	CK_ATTRIBUTE_PTR priv_class;
	CK_ULONG typeval;
	gchar* typestr = NULL;
    int rv = CKR_OK;

	if (!uri || !uri_data)
		return FALSE;

    apimodule_uri_data_init(uri_data); 

    key_uri = p11_kit_uri_new();

    /* Parse the PKCS11 URI */
    if ((rv = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_ANY, key_uri)) != P11_KIT_URI_OK) {
        k_debug_msg("p11_kit_uri_parse failed with error code: %d",  rv);
		goto out;
    }

    /* we expect token label must be present */
    tokenInfo = p11_kit_uri_get_token_info(key_uri);
    if (!tokenInfo || (!tokenInfo->label[0])) {
        k_debug_msg("p11_kit_uri_get_token_info() failed!");
		goto out;
    }


    // We expect Key Label and Key ID
    if ((label_attr = p11_kit_uri_get_attribute (key_uri, CKA_LABEL)) == NULL) {
        k_debug_msg("p11_kit_uri_get_attribute failed for CKA_LABEL (got NULL value)");
		goto out;
    }

    if ((id_attr = p11_kit_uri_get_attribute (key_uri, CKA_ID)) == NULL) {
        k_debug_msg("p11_kit_uri_get_attribute failed for CKA_ID (got NULL value)");
		goto out;
    }

    typestr = g_strrstr(uri,"type=");
    if(typestr != NULL)
    {
    	if ((priv_class = p11_kit_uri_get_attribute (key_uri, CKA_CLASS)) == NULL) {
		k_critical_msg("p11_kit_uri_get_attribute failed for CKA_CLASS (got NULL value)");
		goto out;
	}
	uri_data->type = *((CK_ULONG *)priv_class->pValue);
	if(uri_data->type != CKO_SECRET_KEY && uri_data->type != CKO_PRIVATE_KEY )
	{
		k_critical_msg("Incompatible type in uri for key-id");
		goto out;
	}
    }
    if ((upin = (char*) p11_kit_uri_get_pin_value(key_uri)) == NULL) {
        k_debug_msg("Getting upin from PKCS#11 URI failed");
		goto out;
    }

   	if ((uri_data->token_label = apimodule_utf8_to_char(tokenInfo->label, sizeof(tokenInfo->label))) == NULL)
		goto out;

	uri_data->key_label = g_string_new(NULL);
	uri_data->key_id = g_string_new(NULL);
	uri_data->pin = g_string_new(NULL);

	g_string_append_len(uri_data->key_label, label_attr->pValue, label_attr->ulValueLen);
	g_string_append_len(uri_data->key_id, id_attr->pValue, id_attr->ulValueLen);
	g_string_assign(uri_data->pin, upin);
	ret = TRUE;
out:
    p11_kit_uri_free(key_uri);

    return ret;
}

CK_RV
apimodule_findtoken(apimodule_uri_data *data, gboolean *is_token_present)
{
    CK_RV rv = CKR_OK;
    CK_ULONG nslots=0, n;
    CK_SLOT_ID *slots = NULL;
    CK_TOKEN_INFO   token_info;

    *is_token_present = FALSE;
    if (!data || !is_token_present) {
        rv = CKR_ARGUMENTS_BAD;
        goto end;
    }

    rv = func_list->C_GetSlotList(FALSE, NULL_PTR, &nslots);
    if ((rv != CKR_OK) || !nslots) {
        k_info_msg("C_GetSlotList failed to get no.of.slots %d", nslots);
        goto end;
    }

    // Allocate slot memory
    slots = (CK_SLOT_ID*) calloc(nslots, sizeof(CK_SLOT_ID));
    if (!slots) {
        k_info_msg("Couldn't allocate memory for Slot Info details");
        goto end;
    }

    rv = func_list->C_GetSlotList(FALSE, slots, &nslots);
    if ((rv != CKR_OK) || !nslots) {
        k_info_msg("C_GetSlotList failed to get no.of.slots %d", nslots);
        goto end;
    }

    for (n = 0; n < nslots; n++) {

    	GString *token_label = NULL;
		k_debug_msg("%s - slot %d", __func__, slots[n]);

        if ((rv = func_list->C_GetTokenInfo(slots[n], &token_info)) != CKR_OK)
            continue;

        // Ignore the error cases. continue the loop
        if ((token_label = apimodule_utf8_to_char(token_info.label, sizeof(token_info.label))) == NULL)
            continue;

		g_string_truncate(token_label, data->token_label->len);

		k_debug_msg("checking: %s:%d %s:%d", token_label->str, token_label->len, data->token_label->str, data->token_label->len);
        if (g_string_equal(token_label, data->token_label)) {
            data->slot_id = slots[n];
            *is_token_present = TRUE;
            k_debug_msg("Token: %s already present!", data->token_label->str);
		}
		g_string_free(token_label, TRUE);
		if (*is_token_present)
            break;
    }
end:
    if(slots) free(slots);
    return rv;
}

CK_RV
apimodule_createtoken(apimodule_uri_data *uri_data, CK_SESSION_HANDLE_PTR phSession)
{
    CK_RV rv = CKR_OK;
    CK_ULONG nslots = 0;
    CK_SLOT_ID slot_id = 0;

    if (!uri_data || !phSession) {
        rv = CKR_ARGUMENTS_BAD;
        goto end;
    }

    // Find available token, Last token is uninitialized.. use it
    rv = func_list->C_GetSlotList(FALSE, NULL_PTR, &nslots);
    if ((rv != CKR_OK) || !nslots) {
        k_info_msg("C_GetSlotList failed to get no.of.slots %d", nslots);
        goto end;
    }

    slot_id = nslots - 1;
	GString *label = g_string_new("                               ");
	g_string_prepend(label, uri_data->token_label->str);
	g_string_truncate(label, 32);
    /* We know that the slot is present but token is not present/initialized. Initialize token now */
    if ((rv = func_list->C_InitToken(slot_id, (unsigned char*)uri_data->pin->str, uri_data->pin->len, (unsigned char*)label->str)) != CKR_OK) {
        k_debug_msg("%s failed for slot_id: %lu !: 0x%lx\n", "C_InitToken", slot_id, rv);
        goto end;
    }
	g_string_free(label, TRUE);

    k_debug_msg("%s: slot position/id selected: 0x%lx \n", __func__, slot_id);

    if ((rv = func_list->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, phSession)) != CKR_OK) {
        k_debug_msg("%s failed!: 0x%lx\n", "C_OpenSession", rv);
        goto end;
    }

    rv = func_list->C_Login(*phSession,CKU_SO, (unsigned char*)uri_data->pin->str, uri_data->pin->len);
    if (rv == CKR_USER_ALREADY_LOGGED_IN)
        rv = CKR_OK;

    if (rv != CKR_OK) {
        k_debug_msg("%s failed!: 0x%lx\n", "C_Login", rv);
        goto end;
    }

    // Don't initialize user pin if it is initialized already
    // Initialize the user pin
    if ((rv = func_list->C_InitPIN(*phSession, (unsigned char*) uri_data->pin->str, uri_data->pin->len)) != CKR_OK) {
        k_debug_msg("Unable to set user pin ! rv: %lu \n", rv);
        goto end;
    }

    func_list->C_Logout(*phSession);
    rv = func_list->C_Login(*phSession,CKU_USER, (unsigned char*)uri_data->pin->str, uri_data->pin->len);
    if (rv == CKR_USER_ALREADY_LOGGED_IN)
        rv = CKR_OK;

    if (rv != CKR_OK) {
        k_debug_msg("%s failed!: 0x%lx\n", "user C_Login", rv);
        goto end;
    }
end:
    return rv;
}


#define ATTR_METHOD(ATTR, TYPE) \
static TYPE \
get##ATTR(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj) \
{ \
    TYPE        type = 0; \
    CK_ATTRIBUTE    attr = { CKA_##ATTR, &type, sizeof(type) }; \
    CK_RV       rv; \
 \
    rv = func_list->C_GetAttributeValue(sess, obj, &attr, 1); \
    if (rv != CKR_OK) \
        k_debug_msg("C_GetAttributeValue(" #ATTR ")", rv); \
    return type; \
}

#define VARATTR_METHOD(ATTR, TYPE) \
static TYPE * \
get##ATTR(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount) \
{ \
    CK_ATTRIBUTE    attr = { CKA_##ATTR, NULL, 0 };     \
    CK_RV       rv;                 \
    if (pulCount)                       \
        *pulCount = 0;                  \
    rv = func_list->C_GetAttributeValue(sess, obj, &attr, 1); \
    if (rv == CKR_OK) {                 \
        if (attr.ulValueLen == (CK_ULONG)(-1))      \
            return NULL;                \
        if (!(attr.pValue = calloc(1, attr.ulValueLen + 1)))        \
            k_debug_msg("out of memory in get" #ATTR ": %m");    \
        rv = func_list->C_GetAttributeValue(sess, obj, &attr, 1);     \
        if (attr.ulValueLen == (CK_ULONG)(-1)) {    \
            free(attr.pValue);          \
            return NULL;                \
        }                       \
        if (pulCount)                   \
            *pulCount = attr.ulValueLen / sizeof(TYPE); \
    } else {                        \
        k_debug_msg("C_GetAttributeValue(" #ATTR ")", rv); \
    }                           \
    return (TYPE *) attr.pValue;                \
}

/*
 * Define attribute accessors
 */
ATTR_METHOD(CLASS, CK_OBJECT_CLASS);


void 
apimodule_list_objects(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS  object_class)
{
    CK_OBJECT_HANDLE object;
    CK_ULONG count;
    CK_RV rv;

    rv = func_list->C_FindObjectsInit(sess, NULL, 0);
    if (rv != CKR_OK) {
        k_debug_msg("C_FindObjectsInit", rv);
		return;
	}

    while (1) {
        rv = func_list->C_FindObjects(sess, &object, 1, &count);
        if (rv != CKR_OK) {
            k_debug_msg("C_FindObjects", rv);
			return;
		}
        if (count == 0)
            break;
        if ((int) object_class == -1 || object_class == getCLASS(sess, object))
			k_debug_msg("found an object %d", getCLASS(sess, object));
    }
    func_list->C_FindObjectsFinal(sess);
}

CK_RV 
apimodule_findobject(CK_SESSION_HANDLE hSession, apimodule_uri_data *data, gboolean *is_present)
{
    CK_RV rv = CKR_OK;
    CK_OBJECT_HANDLE hObjects[16] = {0};
    CK_ULONG ulObjectCount = 0;
    gchar dummy[] = "";

    CK_ATTRIBUTE attribs[] = {
        { CKA_LABEL, dummy, strlen(dummy) },
        { CKA_ID, dummy, strlen(dummy) }
    };

    if (!data || !is_present)
        return CKR_ARGUMENTS_BAD;

    *is_present = FALSE;
    attribs[0].ulValueLen = data->key_label->len;
    attribs[0].pValue = data->key_label->str;
    attribs[1].ulValueLen = data->key_id->len;
    attribs[1].pValue = data->key_id->str;
    rv = func_list->C_FindObjectsInit(hSession,&attribs[0],2);
    rv = func_list->C_FindObjects(hSession,&hObjects[0],16,&ulObjectCount);
    rv = func_list->C_FindObjectsFinal(hSession);

    if(ulObjectCount > 0) {
        k_debug_msg("Object Found: Label %s, count %d",  data->key_label->str, ulObjectCount);
        *is_present = TRUE;
	    CK_ULONG obj_class;
	    CK_ATTRIBUTE tmpl[] = {
		    {CKA_CLASS, &obj_class, sizeof(obj_class) }
	    };
	    rv = func_list->C_GetAttributeValue(hSession, hObjects[0], tmpl, 1);

	    k_debug_msg("C_GetAttributeValue %d %s", rv,
		    (obj_class == CKO_PRIVATE_KEY ? "private" : (obj_class == CKO_SECRET_KEY ? "secret" : "other")));
    }
    return rv;
}

void
apimodule_hexdump(char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

apimodule_token *
alloc_apimodule_token(const char *label, const char *pin)
{
    apimodule_token *atoken = (apimodule_token *)calloc(1,sizeof(apimodule_token));
    atoken->token_label = g_string_new(label);
    atoken->pin = g_string_new(pin);
    atoken->use_token_objects = FALSE;
    atoken->challenge = NULL;
    atoken->session = CK_INVALID_HANDLE;
    atoken->publickey_challenge_handle = CK_INVALID_HANDLE;
    atoken->privatekey_challenge_handle = CK_INVALID_HANDLE;
    atoken->wrappingkey_handle = CK_INVALID_HANDLE;
    k_debug_msg("%s:%s:%s", __func__, label, atoken->token_label->str);
    return atoken;
}

void
free_apimodule_token(apimodule_token *atoken)
{
    if (atoken->token_label) g_string_free(atoken->token_label, TRUE);
    if (atoken->pin) g_string_free(atoken->pin, TRUE);
    free(atoken);
}

apimodule_token *
lookup_apimodule_token(const char *label)
{
    return (apimodule_token *)g_hash_table_lookup (apimodule_token_hash, label);
}

gboolean
cache_apimodule_token(apimodule_token *atoken)
{
    k_debug_msg("%s:%p:%s", __func__, atoken, atoken->token_label->str);
    return g_hash_table_insert(apimodule_token_hash, atoken->token_label->str, atoken);
}

apimodule_token *
init_apimodule_token(apimodule_uri_data *uri_data, gboolean create, GError **err)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    apimodule_token *atoken = alloc_apimodule_token(uri_data->token_label->str, uri_data->pin->str);
    gboolean is_present = FALSE;
    CK_SESSION_HANDLE hSession;


    if (!atoken) return NULL;

    do {
        // Find slot_id for the token, if present
   	    if ((rv = apimodule_findtoken(uri_data, &is_present)) != CKR_OK) {
       	    k_set_error(err, -1, "Error query token");
		    break;
   	    }

    	// If no token present, create a new token
    	if (!is_present) {
            if (!create) {
                rv = CKR_GENERAL_ERROR;
                break;
            }
        	// Create Token, Open Session, SO login and Init user pin
        	if ((rv = apimodule_createtoken(uri_data, &hSession)) != CKR_OK) {
        		k_set_error(err, -1, "failed to create token");
				break;
        	}
			k_debug_msg("token created");
    		func_list->C_Logout(hSession);
    		func_list->C_CloseSession(hSession);
    	} 

		k_debug_msg("find-token after token create");
    	if (((rv = apimodule_findtoken(uri_data, &is_present)) != CKR_OK) || !is_present) {
        	k_set_error(err, -1, "Error query token");
        	k_info_msg("Error query token");
			break;
    	}
    	if ((rv = func_list->C_OpenSession(uri_data->slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession)) != CKR_OK) {
    		k_set_error(err, -1, "failed to open session on  token");
			break;
    	}
    	rv = func_list->C_Login(hSession,CKU_USER, (unsigned char*)uri_data->pin->str, uri_data->pin->len);
    	func_list->C_Logout(hSession);
    	rv = func_list->C_Login(hSession,CKU_USER, (unsigned char*)uri_data->pin->str, uri_data->pin->len);
        if (rv == CKR_USER_ALREADY_LOGGED_IN)
            rv = CKR_OK;

        if (rv != CKR_OK) {
    		k_set_error(err, -1, "failed to login on token");
			break;
        }
		atoken->session = hSession;
    } while (FALSE);

    if (rv != CKR_OK) {
        free_apimodule_token(atoken);
        atoken = NULL;
    } else
        cache_apimodule_token(atoken);

	k_debug_msg("%s:%d: atoken %p", __func__, __LINE__, atoken);

    return atoken;
}
