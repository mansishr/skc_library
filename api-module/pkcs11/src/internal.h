#ifndef __APIMODULE_INTERNAL__
#define __APIMODULE_INTERNAL__

#include <glib.h>
#include "k_errors.h"
#include <p11-kit/uri.h>
#include <key-agent/key_agent.h>

typedef struct {
	GString *token_label;
	GString *key_label;
	GString *key_id;
	GString *pin;
	CK_ULONG type;
    CK_SLOT_ID slot_id;
} apimodule_uri_data;

typedef struct {
	GString *token_label;
    gboolean use_token_objects;
	GString *pin;
    k_buffer_ptr challenge;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE publickey_challenge_handle;
    CK_OBJECT_HANDLE privatekey_challenge_handle;
    CK_OBJECT_HANDLE wrappingkey_handle;
} apimodule_token;

#define PKCS11_APIMODULE_QUOTELABEL "quoting-key"
#define PKCS11_APIMODULE_QUOTEID    "80000001"
#define PKCS11_APIMODULE_SWKLABEL 	"SWK"
#define PKCS11_APIMODULE_SWKID    	"80000002"

extern gboolean use_token_objects;

static CK_BBOOL bFalse = CK_FALSE;
static CK_BBOOL bTrue = CK_TRUE;

#define SET_TOKEN_ATTRIBUTE(TEMPLATE,INDEX) do { \
    if (use_token_objects) { \
        TEMPLATE[INDEX].ulValueLen = sizeof(bTrue); \
        TEMPLATE[INDEX].pValue = &bTrue; \
    } else { \
        TEMPLATE[INDEX].ulValueLen = sizeof(bFalse); \
        TEMPLATE[INDEX].pValue = &bFalse; \
    } \
} while(0)

#define DEFAULT_SPID_LEN 	32    
#define CKM_AES_KEY_WRAP        (0x2109UL)
#define CKM_AES_KEY_WRAP_PAD    (0x210aUL)

#ifndef CKM_AES_GCM
#define CKM_AES_GCM            	(0x1087UL)
#endif

#ifndef CKZ_DATA_SPECIFIED
#define CKZ_DATA_SPECIFIED     	(0x00000001UL)
#endif

#ifdef  __cplusplus
extern "C" {
#endif

extern keyagent_apimodule_ops *sgx_apimodule_ops;
extern keyagent_apimodule_ops *sw_apimodule_ops;
extern GHashTable *apimodule_token_hash;
extern GHashTable *apimodule_api_hash;
extern GHashTable *module_hash;
extern CK_FUNCTION_LIST_PTR func_list;

gboolean apimodule_uri_to_uri_data(const char *uri, apimodule_uri_data *uri_data);
void apimodule_uri_data_cleanup(apimodule_uri_data *uri_data);
void apimodule_uri_data_init(apimodule_uri_data *uri_data);

CK_RV apimodule_findtoken(apimodule_uri_data *data, gboolean *is_token_present);
CK_RV apimodule_createtoken(apimodule_uri_data *uri_data, CK_SESSION_HANDLE_PTR phSession);
CK_RV apimodule_findobject(CK_SESSION_HANDLE hSession, apimodule_uri_data *data, gboolean *is_present);

void apimodule_list_objects(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS  object_class);
void apimodule_hexdump(char *desc, void *addr, int len);

gboolean init_keyagent(void);

apimodule_token *alloc_apimodule_token(const char *label, const char *pin);
apimodule_token *lookup_apimodule_token(const char *label);
gboolean cache_apimodule_token(apimodule_token *atoken);
void free_apimodule_token(apimodule_token *atoken);
apimodule_token *init_apimodule_token(apimodule_uri_data *uri_data, gboolean create, GError **err);
gboolean convert_hexstring_to_byte_array(unsigned char *dest, const void *vsrc, size_t len);

#ifdef  __cplusplus
}
#endif

#endif
