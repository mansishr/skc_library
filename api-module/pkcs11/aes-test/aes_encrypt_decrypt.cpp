#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <memory.h>       
#include <vector>       
#include <p11-kit-1/p11-kit/pkcs11.h>

#include <openssl/bio.h>
#include <openssl/pem.h>

#include <glib.h>
#include <gmodule.h>
#include "key-agent/key_agent.h"

#ifdef __cplusplus
extern "C" {
#endif


static CK_RV (*c_ondemand_keyload)(const char *url);

#ifdef __cplusplus
}
#endif
CK_FUNCTION_LIST_PTR func_list;


#define RV_CHECK(fn, rv) \
do { \
    if((rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)) { \
        fprintf(stderr, "%s() failed: 0x%lx ! \n", fn, rv); \
	exit(0); \
    } \
    else { \
    } \
}while(0);

#define print_vector(printString, vectorData) \
do { \
    std::vector<CK_BYTE>::iterator it; \
    if(!vectorData.size()) { \
        fprintf(stdout, "Empty vector - #vectorData ! \n"); \
    } \
    else { \
        fprintf(stdout, "%s \n", printString); \
        for(it = vectorData.begin(); it != vectorData.end(); it++) { \
            CK_BYTE value = *it; \
            fprintf(stdout, " 0x%02x", value); \
        } \
        fprintf(stdout, "\n"); \
    } \
} while(0);

#define print_CK_BYTE(printString, data , len) \
do { \
    fprintf(stdout, "%s \n", printString); \
    for (unsigned int i=0; i < len; i++) { \
        fprintf(stdout, " %d", data[i]); \
    } \
    fprintf(stdout, "\n"); \
} while(0);

static char *utf8_to_char(CK_UTF8CHAR *utf8buf, size_t len)
{
    static char *charBuffer;
    size_t      inCount=0, outCount=0;

    if(len <= 0)
       return NULL;

    while (len && utf8buf[len-1] == ' ')
        len--;

    if(len <= 0)
        return NULL;

    charBuffer = (char *) malloc (len+1);
    if(!charBuffer)
        return NULL;

    for (inCount = outCount = 0; inCount < len; inCount++) {
        charBuffer[inCount] = utf8buf[outCount++];
    }
    charBuffer[inCount] = '\0';

    return charBuffer;
}

CK_RV FindToken(const char* input_token_label,
                        gboolean* is_token_present,
                        CK_SLOT_ID* slot_id)
{
    CK_RV rv = CKR_OK;
    CK_ULONG nslots=0, label_len=0, n;
    CK_SLOT_ID *slots = NULL;
    CK_TOKEN_INFO   token_info;
    char* current_token_label = NULL;

    if( (!input_token_label) || (!is_token_present) ) {
        rv = CKR_ARGUMENTS_BAD;
        goto end;
    }
    *is_token_present = false;

    rv = func_list->C_GetSlotList(FALSE, NULL_PTR, &nslots);
    if((rv != CKR_OK) || (nslots == 0) ) {
        fprintf(stderr, "func_list->C_GetSlotList failed to get no.of.slots %lu \n", nslots);
        goto end;
    }

    // Allocate slot memory
    slots = (CK_SLOT_ID*) malloc(nslots * sizeof(CK_SLOT_ID));
    if(!slots) {
        fprintf(stderr, "Couldn't allocate memory for Slot Info details \n");
        goto end;
    }

    rv = func_list->C_GetSlotList(FALSE, slots, &nslots);
    if((rv != CKR_OK) || (nslots == 0)) {
        fprintf(stderr, "func_list->C_GetSlotList failed to get all slot info. no.of slots: %lu \n", nslots);
        goto end;
    }

    label_len = strlen(input_token_label);
    for (n = 0; n < nslots; n++) {
        rv = func_list->C_GetTokenInfo(slots[n], &token_info);
        if (rv != CKR_OK) {
            continue;
        }
        current_token_label = utf8_to_char(token_info.label, sizeof(token_info.label));
        if(current_token_label == NULL) {
            // Ignore the error cases. continue the loop
            continue;
        }
        if (!strncmp(current_token_label, input_token_label, label_len)) {
            *slot_id = slots[n];
            *is_token_present = true;
            fprintf(stdout, "Token: %s already present! \n", input_token_label);
            break;
        }
    }

end:
    if(current_token_label) {
        free(current_token_label);
    }
    if(slots) {
        free(slots);
    }
    return rv;
}

CK_RV
load_module(const char *module_name, CK_FUNCTION_LIST_PTR_PTR funcs)
{
    GModule *mod = NULL;
    CK_RV rv, (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
    rv = CKR_GENERAL_ERROR;
    g_return_val_if_fail(module_name, CKR_GENERAL_ERROR );
    do {
        mod = g_module_open(module_name, G_MODULE_BIND_LOCAL);
        if (!mod) {
            k_critical_msg("%s: %s", module_name, g_module_error ());
            break;
        }
        if (!g_module_symbol(mod, "C_GetFunctionList", (gpointer *)&c_get_function_list)) {
            k_critical_msg("%s: invalid pkcs11 module", module_name);
            break;
        }
        if (!g_module_symbol(mod, "C_OnDemand_KeyLoad", (gpointer *)&c_ondemand_keyload)) {
            k_critical_msg("%s: can't find C_OnDemand_KeyLoad", module_name);
            break;
        }

        if ((rv = c_get_function_list(funcs)) == CKR_OK) {
           return CKR_OK;
        } else
            k_critical_msg("C_GetFunctionList failed %lx", rv);
    } while (FALSE);
    return rv; 
}

                                             
int main(int argc, char* argv[])
{
    CK_RV                rv = 0;
    CK_C_INITIALIZE_ARGS initArgs;
    CK_SESSION_HANDLE    hSession = 0;

    CK_OBJECT_HANDLE hObjects;
    CK_ULONG ulObjectCount = 0;
    CK_BYTE plainText[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	    0x00 };
    std::vector<CK_BYTE> vEncryptedData;
    std::vector<CK_BYTE> vDecryptedData;
    CK_ULONG ulEncryptedDataLen;
    CK_ULONG ulDataLen;
    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
    gboolean present = false;
    CK_SLOT_ID slot_id;

    // Input values like NPM module name and key-id are changed as per KMS key values
    gchar inputPart1[] = "pkcs11:model=DHSM%20v2;type=private;object=test;token=";
    gchar idStr[] = "id=";
    gchar pinStr[] = "pin-value=";
    gchar pin[] = "1234";
    gchar *inputString = NULL;
    gchar* token_name = argv[1];
    gchar* key_id = argv[2];
    CK_UTF8CHAR label[] = "test";
    CK_BYTE iv[]= {  0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    if( (argc < 2) || (!token_name) || (!key_id) ) {
        fprintf(stderr, "Invalid no.of Arguments. Make sure Token name and key_id passed as input ! \n");
        return -1;
    }    

    inputString = g_strconcat(inputPart1, token_name, ";", idStr, key_id, ";", pinStr, pin, NULL);
    if(!inputString) {
        fprintf(stderr, "Error forming PKCS11 URI from input values ! \n");
        return -1;
    }
    fprintf(stdout, "inputString: %s \n", inputString);

    CK_OBJECT_CLASS privClass = CKO_SECRET_KEY;
    CK_ATTRIBUTE attribs[] = {
	    { CKA_CLASS, &privClass, sizeof(privClass) },
	    { CKA_LABEL, label, sizeof(label)-1 },
	    //{ CKA_ID, (CK_UTF8CHAR_PTR)key_id, strlen(key_id) }
    };

    GString *module_path=g_string_new(getenv("INSTALLDIR"));
    g_string_append(module_path, "/lib/libpkcs11-api.so");
    if (load_module(module_path->str, &func_list) != CKR_OK) {
        fprintf(stderr, "Error loading module\n");
        return -1;
    }

    CK_MECHANISM mechanism = { CKM_AES_CBC, NULL_PTR, 0 };
    //rv = C_GetFunctionList(&func_list);
    //RV_CHECK("func_list->C_GetFunctionList", rv);



    memset( &initArgs, (size_t)sizeof( CK_C_INITIALIZE_ARGS ), 0);
    initArgs.flags = CKF_OS_LOCKING_OK;       // -> let PKCS11 use its own locking
    rv = func_list->C_Initialize( NULL );
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED ) {
        fprintf(stderr, "PKCS11: failed func_list->C_Initialize (error:%lx)", rv );
        return -1;
    }



    if(CKR_OK != c_ondemand_keyload(inputString))
    {
        g_free(inputString);
        return -1;
    }
    g_free(inputString);

    rv = FindToken(token_name, &present, &slot_id);
    if(!present) {
        fprintf(stderr, "Token %s not found \n", token_name);
        goto err;
    }
    // Open read-write session
    rv = func_list->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
    RV_CHECK("C_OpenSession", rv);

    // Login USER into the sessions so we can create a private objects
    rv = func_list->C_Login(hSession,CKU_USER,(unsigned char*)pin,strlen(pin));
    if ( rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
    {
        fprintf(stderr, "C_Login\n");
	goto err;
    }


    // Now find the objects while logged in should find them all.
    rv = func_list->C_FindObjectsInit(hSession,&attribs[0], 2);
    if ( rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
    {
        fprintf(stderr, "C_FindObjectsInit\n");
	goto err;
    }


    rv = func_list->C_FindObjects(hSession,&hObjects,1,&ulObjectCount);
    RV_CHECK("C_FindObjects", rv);
    fprintf(stdout, "No.of Secret objects found: %ld \n", ulObjectCount);


    if( ulObjectCount != 1 )
    {
        fprintf(stderr, "C_FindObjects object not found\n");
	goto err;
    }



    rv = func_list->C_FindObjectsFinal(hSession);
    hKey = hObjects;

    mechanism.pParameter = iv;
    mechanism.ulParameterLen = sizeof(iv);


    print_CK_BYTE("Plain text:", plainText, sizeof(plainText)-1);
    // Single-part encryption
    rv = func_list->C_EncryptInit(hSession,&mechanism,hKey);
    RV_CHECK("C_EncryptInit", (rv));
    rv = func_list->C_Encrypt(hSession,plainText,sizeof(plainText)-1,NULL_PTR,&ulEncryptedDataLen) ;
    RV_CHECK("func_list->C_Encrypt", rv);
    vEncryptedData.resize(ulEncryptedDataLen);
    rv = func_list->C_Encrypt(hSession,plainText,sizeof(plainText)-1,&vEncryptedData.front(),&ulEncryptedDataLen) ;
    RV_CHECK("func_list->C_Encrypt", rv);
    vEncryptedData.resize(ulEncryptedDataLen);
    print_vector("Encrypted Data:", vEncryptedData);

    rv = func_list->C_DecryptInit(hSession,&mechanism,hKey);
    RV_CHECK("func_list->C_DecryptInit", rv );
    rv = func_list->C_Decrypt(hSession,&vEncryptedData.front(),vEncryptedData.size(),NULL_PTR,&ulDataLen);
    RV_CHECK("func_list->C_Decrypt", rv );
    vDecryptedData.resize(ulDataLen);
    rv = func_list->C_Decrypt(hSession,&vEncryptedData.front(),vEncryptedData.size(),&vDecryptedData.front(),&ulDataLen);
    RV_CHECK("func_list->C_Decrypt", rv );
    vDecryptedData.resize(ulDataLen);
    print_vector("Decrypted data:", vDecryptedData);

    func_list->C_CloseSession(hSession);
    func_list->C_Logout(hSession);

err:
    return rv;
}

