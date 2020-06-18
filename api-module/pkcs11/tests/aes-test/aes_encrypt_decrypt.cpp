#include <vector>       
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <gmodule.h>
#include <unistd.h>
#include <sys/wait.h> 
#include "config.h"
#include "api-module/pkcs11/src/internal.h"

#ifdef __cplusplus
extern "C" {
#endif

CK_RV do_aes_encrypt_decrypt(apimodule_uri_data *uri_data);
static CK_RV (*c_ondemand_keyload)(const char *url);
gboolean (*parse_uri_data)(const char *uri, apimodule_uri_data *uri_data);
gboolean (*clean_uri_data)(apimodule_uri_data *uri_data);
apimodule_uri_data uri_data;
gchar* uri = NULL;

#ifdef __cplusplus
}
#endif
CK_FUNCTION_LIST_PTR func_list;

#define RV_CHECK(fn, rv) \
do { \
    if((rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)) { \
        fprintf(stderr, "%s() failed: 0x%lx ! \n", fn, rv); \
		goto err; \
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
    size_t inCount=0, outCount=0;

    if(len <= 0)
       return NULL;

    while(len && utf8buf[len-1] == ' ')
        len--;

    if(len <= 0)
        return NULL;

    charBuffer = (char *)malloc(len+1);
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
    CK_TOKEN_INFO token_info;
    char* current_token_label = NULL;

    if((!input_token_label) || (!is_token_present)) {
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
    slots = (CK_SLOT_ID*)malloc(nslots * sizeof(CK_SLOT_ID));
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
        if(rv != CKR_OK) {
            continue;
        }
        current_token_label = utf8_to_char(token_info.label, sizeof(token_info.label));
        if(current_token_label == NULL) {
            // Ignore the error cases. continue the loop
            continue;
        }
        if(!strncmp(current_token_label, input_token_label, label_len)) {
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
        if(!mod) {
            k_critical_msg("%s: %s", module_name, g_module_error());
            break;
        }
        if(!g_module_symbol(mod, "C_GetFunctionList", (gpointer *)&c_get_function_list)) {
            k_critical_msg("%s: invalid pkcs11 module", module_name);
            break;
        }
        if(!g_module_symbol(mod, "C_OnDemand_KeyLoad", (gpointer *)&c_ondemand_keyload)) {
            k_critical_msg("%s: can't find C_OnDemand_KeyLoad", module_name);
            break;
        }
        if(!g_module_symbol(mod, "apimodule_uri_to_uri_data", (gpointer *)&parse_uri_data)) {
            k_critical_msg("%s: can't find apimodule_uri_to_uri_data", module_name);
            break;
        }
        if(!g_module_symbol(mod, "apimodule_uri_data_cleanup", (gpointer *)&clean_uri_data)) {
            k_critical_msg("%s: can't find apimodule_uri_data_cleanup", module_name);
            break;
        }

        if((rv = c_get_function_list(funcs)) == CKR_OK) {
           return CKR_OK;
        } else
            k_critical_msg("C_GetFunctionList failed %lx", rv);
    }while(FALSE);
    return rv; 
}

CK_RV do_aes_encrypt_decrypt(apimodule_uri_data *uri_data)
{
    CK_RV rv = 0;
    CK_C_INITIALIZE_ARGS initArgs;
    CK_SESSION_HANDLE hSession = 0;

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

    CK_BYTE iv[]= {  0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    CK_OBJECT_CLASS privClass = CKO_SECRET_KEY;
    CK_ATTRIBUTE attribs[] = {
	    { CKA_CLASS, &privClass, sizeof(privClass) },
	    { CKA_ID, (CK_UTF8CHAR_PTR)uri_data->key_id->str, strlen(uri_data->key_id->str) }
    };
    CK_MECHANISM mechanism = { CKM_AES_CBC, NULL_PTR, 0 };

    memset(&initArgs, (size_t)sizeof(CK_C_INITIALIZE_ARGS), 0);
    initArgs.flags = CKF_OS_LOCKING_OK;
    rv = func_list->C_Initialize(NULL);
    if(rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        fprintf(stderr, "PKCS11: failed func_list->C_Initialize (error:%lx)", rv );
	goto err;
    }

    if(CKR_OK != c_ondemand_keyload(uri))
    {
        fprintf(stderr, "PKCS11: OnDemand KeyLoad failed\n");
	goto err;
    }

    rv = FindToken(uri_data->token_label->str, &present, &slot_id);
    if(!present) {
        fprintf(stderr, "Token %s not found \n", uri_data->token_label->str);
        goto err;
    }
    // Open read-write session
    rv = func_list->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
    RV_CHECK("C_OpenSession", rv);

    // Login USER into the sessions so we can create a private objects
    rv = func_list->C_Login(hSession,CKU_USER,(unsigned char*)uri_data->pin->str,strlen(uri_data->pin->str));
    if(rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
    {
        fprintf(stderr, "C_Login\n");
	    goto err;
    }
    // Now find the objects while logged in should find them all.
    rv = func_list->C_FindObjectsInit(hSession,&attribs[0], 2);
    if(rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
    {
        fprintf(stderr, "C_FindObjectsInit\n");
		goto err;
    }

    rv = func_list->C_FindObjects(hSession,&hObjects,1,&ulObjectCount);
    RV_CHECK("C_FindObjects", rv);
    fprintf(stdout, "No.of Secret objects found: %ld \n", ulObjectCount);

    if(ulObjectCount != 1)
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

void* thread_aes_encrypt_decrypt_test(void *x)
{
        apimodule_uri_data  *data = (apimodule_uri_data *)x;
        do_aes_encrypt_decrypt(data);
        return NULL;
}
                                             
int main(int argc, char* argv[])
{
    uri = argv[1];
    pthread_t thread;
    pid_t forkStatus;
    CK_RV rv;

    if((argc < 1) || (!uri)) {
        fprintf(stderr, "Invalid no.of Arguments. Please run %s <URI>\n", argv[0]);
        return -1;
    }    
    
    GString *module_path=NULL;
    if(getenv("INSTALLDIR") != NULL)
    	     module_path = g_string_new(getenv("INSTALLDIR"));
    else
    	     module_path = g_string_new(SKC_INSTALL_DIR);

    g_string_append(module_path, "/lib/libpkcs11-api.so");
    if(load_module(module_path->str, &func_list) != CKR_OK) {
        fprintf(stderr, "Error loading module\n");
        return -1;
    }
    g_string_free(module_path, false);

    if(parse_uri_data(uri, &uri_data) != TRUE){
        fprintf(stderr, "Error in parsing pkcs11 uri %s <URI>\n", uri);
        return -1;
    }    
   
    rv = do_aes_encrypt_decrypt(&uri_data);    

#ifndef FORK_TEST
    if(pthread_create(&thread, NULL, thread_aes_encrypt_decrypt_test, (void *)&uri_data)) {
	fprintf(stderr, "Error creating thread\n");
	return -1;
    }
	
    if(pthread_join(thread, NULL)) {
	fprintf(stderr, "Error joining thread\n");
	return -1;
    }

    forkStatus = fork();

    /* Child... */
    if(forkStatus == 0) {
	rv = do_aes_encrypt_decrypt(&uri_data);
	/* Parent... */
    } else if(forkStatus != -1) {
	wait(NULL);
	rv = do_aes_encrypt_decrypt(&uri_data);
    } else {
	perror("Error while calling the fork function");
    }

#endif

    clean_uri_data(&uri_data);
    return 0;
}
