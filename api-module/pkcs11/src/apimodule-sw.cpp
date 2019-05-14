#define G_LOG_DOMAIN "apimodule-sw"
#include <p11-kit/pkcs11.h>
#include "config.h"
#include "k_errors.h"
#include "internal.h"

#include "key-agent/key_agent.h"
#include "key-agent/types.h"

static gboolean sw_get_challenge(keyagent_apimodule_get_challenge_details *, void *, GError **err);
static gboolean sw_set_wrapping_key(keyagent_apimodule_session_details *, void *, GError **err);
static gboolean sw_load_key(keyagent_apimodule_loadkey_details *, void *, GError **err);


keyagent_apimodule_ops _sw_apimodule_ops = { 
    .init = NULL,
    .load_uri = NULL, 
    .load_key = sw_load_key,
    .get_challenge = sw_get_challenge,
    .set_wrapping_key = sw_set_wrapping_key
};

keyagent_apimodule_ops *sw_apimodule_ops = &_sw_apimodule_ops;

CK_RV
sw_unwrap_symmeric_key(keyagent_apimodule_loadkey_details *details, apimodule_token *atoken)
{
	//CK_MECHANISM_TYPE mechanismType = CKM_AES_GCM;
	CK_MECHANISM_TYPE mechanismType = CKM_AES_KEY_WRAP;
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_RV rv;
	CK_OBJECT_HANDLE hPrivateKey;
	gboolean ret = FALSE;
    apimodule_uri_data *uri_data            = (apimodule_uri_data *)details->module_data;
    CK_OBJECT_CLASS privClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;

    CK_GCM_PARAMS gcmParams =
    {
        k_buffer_data(details->iv),
        k_buffer_length(details->iv),
        k_buffer_length(details->iv) * 8,
		NULL,
		0,
        details->tag_size*8
    };

	if (mechanismType == CKM_AES_GCM) {
		mechanism.pParameter = &gcmParams;
		mechanism.ulParameterLen = sizeof(gcmParams);
	}

    CK_ATTRIBUTE nPrkAttribs[] = {
        { CKA_TOKEN, 	&bFalse, sizeof(bFalse) },
        { CKA_CLASS, 	&privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_LABEL,    uri_data->key_label->str,        	uri_data->key_label->len },
        { CKA_ID,       uri_data->key_id->str,        		uri_data->key_id->len },
        { CKA_PRIVATE, 	&bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, 	&bTrue, sizeof(bTrue) },
    //    { CKA_SIGN, 	&bTrue,sizeof(bTrue) },
        { CKA_UNWRAP, 	&bTrue, sizeof(bTrue) },
    //    { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };

	SET_TOKEN_ATTRIBUTE(nPrkAttribs, 0);

    hPrivateKey = CK_INVALID_HANDLE;
    rv = func_list->C_UnwrapKey(atoken->session, &mechanism, atoken->wrappingkey_handle, 
		k_buffer_data(details->key), k_buffer_length(details->key), 
		nPrkAttribs, sizeof(nPrkAttribs)/sizeof(CK_ATTRIBUTE), &hPrivateKey);

	return rv;
}

CK_RV
sw_unwrap_rsa_key(keyagent_apimodule_loadkey_details *details, apimodule_token *atoken)
{
	CK_MECHANISM_TYPE mechanismType = CKM_AES_KEY_WRAP;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
    apimodule_uri_data *uri_data            = (apimodule_uri_data *)details->module_data;
	CK_RV rv;

	CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;

	CK_ATTRIBUTE nPrkAttribs[] = {
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_CLASS, &privateClass, sizeof(privateClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_LABEL,    uri_data->key_label->str,        	uri_data->key_label->len },
        { CKA_ID,       uri_data->key_id->str,        		uri_data->key_id->len },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue,sizeof(bTrue) },
		//{ CKA_VERIFY, &bTrue,sizeof(bTrue) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	SET_TOKEN_ATTRIBUTE(nPrkAttribs, 0);

	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };

	hPrk = CK_INVALID_HANDLE;
    rv = func_list->C_UnwrapKey(atoken->session, &mechanism, atoken->wrappingkey_handle, 
		k_buffer_data(details->key), k_buffer_length(details->key), 
		nPrkAttribs, sizeof(nPrkAttribs)/sizeof(CK_ATTRIBUTE), &hPrk);
	return rv;
}

static gboolean 
sw_load_key(keyagent_apimodule_loadkey_details *details, void *extra, GError **err)
{
    gboolean status = FALSE;
    CK_RV rv = CKR_OK;
    apimodule_token *atoken = NULL;
	apimodule_uri_data *data = NULL;

    if (!details || !details->key || !err || !details->module_data) {
        k_set_error(err, -1, "Input parameters are invalid!");
        goto end;
	}

	data = (apimodule_uri_data *)details->module_data;

    if (!data->token_label) {
        k_set_error(err, -1, "Input parameters are invalid!");
        goto end;
	}

    atoken = lookup_apimodule_token(data->token_label->str);

    if (!atoken) {
        k_set_error(err, -1, "Input parameters are invalid!");
        goto end;
	}

	switch (details->type) {
	case KEYAGENT_AESKEY:
		rv = sw_unwrap_symmeric_key(details, atoken);
		break;
	case KEYAGENT_RSAKEY:
		rv = sw_unwrap_rsa_key(details, atoken);
		break;
	default:
		rv = CKR_ARGUMENTS_BAD;  
		break;
	}
    if (rv == CKR_OK)
        status = TRUE;
	else
        k_set_error(err, -1, "Input parameters are invalid!");
end:
    return status;
}

static CK_RV
generate_rsa_keypair(apimodule_token *atoken, const char *label, const char *id)
{
	CK_BBOOL bTokenPuk = CK_TRUE;
	CK_BBOOL bTokenPrk = CK_TRUE;
	CK_BBOOL bPrivatePuk = CK_TRUE;
	CK_BBOOL bPrivatePrk = CK_TRUE; 
    CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_ULONG bits = 2048;
    CK_BYTE pubExp[] = {0x01, 0x00, 0x01};
    CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE rsaKeyType           = CKK_RSA;


    CK_ATTRIBUTE pukAttribs[] = {
        { CKA_TOKEN,    &bTokenPuk, sizeof(bTokenPuk) },
        {CKA_CLASS,     &pubkey_class, sizeof(pubkey_class)},
		{ CKA_KEY_TYPE, &rsaKeyType,        sizeof(rsaKeyType)   },
        { CKA_LABEL,    (void *)label,        		strlen(label) },
        { CKA_ID,       (void *)id,        		strlen(id) },
        { CKA_PRIVATE,  &bPrivatePuk, sizeof(bPrivatePuk) },
        { CKA_ENCRYPT,  &bTrue, sizeof(bTrue) },
        { CKA_VERIFY,   &bTrue, sizeof(bTrue) },
        { CKA_WRAP,     &bTrue, sizeof(bTrue) },
        { CKA_MODULUS_BITS, &bits, sizeof(bits) },
		//{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
//        { CKA_PUBLIC_EXPONENT, &pubExp[0], sizeof(pubExp) }
    };
    CK_ATTRIBUTE prkAttribs[] = {
        { CKA_TOKEN,    &bTokenPrk, sizeof(bTokenPrk) },
        {CKA_CLASS,     &privkey_class, sizeof(privkey_class)},
		{ CKA_KEY_TYPE, &rsaKeyType,        sizeof(rsaKeyType)   },
        { CKA_LABEL,    (void *)label,        		strlen(label) },
        { CKA_ID,       (void *)id,        		strlen(id) },
        { CKA_PRIVATE,  &bPrivatePrk, sizeof(bPrivatePrk) },
        //{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT,  &bTrue, sizeof(bTrue) },
        { CKA_SIGN,     &bTrue, sizeof(bTrue) },
		//{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_UNWRAP,   &bTrue, sizeof(bTrue) },
    };

	SET_TOKEN_ATTRIBUTE(pukAttribs, 0);
	SET_TOKEN_ATTRIBUTE(prkAttribs, 0);

    atoken->publickey_challenge_handle = CK_INVALID_HANDLE;
    atoken->privatekey_challenge_handle = CK_INVALID_HANDLE;

    return func_list->C_GenerateKeyPair(atoken->session, &mechanism,
                             pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
                             prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
                             &atoken->publickey_challenge_handle,
                             &atoken->privatekey_challenge_handle);
}

#ifdef TESTING
CK_RV generateAesKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE &hKey)
{
    CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_ULONG bytes = 16;
    CK_ATTRIBUTE keyAttribs[] = {
        { CKA_TOKEN, &bFalse, sizeof(bTrue) },
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
        { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
        { CKA_VALUE_LEN, &bytes, sizeof(bytes) },
    };

    hKey = CK_INVALID_HANDLE;
    return func_list->C_GenerateKey(hSession, &mechanism,
                 keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
                 &hKey);
}


void rsaWrapUnwrap(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
	CK_BYTE cipherText[2048];
	CK_ULONG ulCipherTextLen;
	CK_BYTE symValue[64];
	CK_ULONG ulSymValueLen = sizeof(symValue);
	CK_BYTE unwrappedValue[64];
	CK_ULONG ulUnwrappedValueLen = sizeof(unwrappedValue);
	CK_OBJECT_HANDLE symKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE unwrappedKey = CK_INVALID_HANDLE;
	CK_RV rv;
	CK_ULONG wrappedLenEstimation;

	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ATTRIBUTE unwrapTemplate[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	CK_ATTRIBUTE valueTemplate[] = {
		{ CKA_VALUE, &symValue, ulSymValueLen }
	};

	CK_MECHANISM_INFO mechInfo;

	if (mechanismType == CKM_RSA_PKCS_OAEP)
	{
		mechanism.pParameter = &oaepParams;
		mechanism.ulParameterLen = sizeof(oaepParams);
	}

	// Generate temporary symmetric key and remember it's value
	rv = generateAesKey(hSession, symKey);
	rv = func_list->C_GetAttributeValue(hSession, symKey, valueTemplate, sizeof(valueTemplate)/sizeof(CK_ATTRIBUTE));
	ulSymValueLen = valueTemplate[0].ulValueLen;

	// Estimate wrapped length
	rv = func_list->C_WrapKey(hSession, &mechanism, hPublicKey, symKey, NULL_PTR, &wrappedLenEstimation);
	ulCipherTextLen = sizeof(cipherText);
	rv = func_list->C_WrapKey(hSession, &mechanism, hPublicKey, symKey, cipherText, &ulCipherTextLen);
	rv = func_list->C_UnwrapKey(hSession, &mechanism, hPrivateKey, cipherText, ulCipherTextLen, unwrapTemplate, sizeof(unwrapTemplate)/sizeof(CK_ATTRIBUTE), &unwrappedKey);
	valueTemplate[0].pValue = &unwrappedValue;
	rv = func_list->C_GetAttributeValue(hSession, unwrappedKey, valueTemplate, sizeof(valueTemplate)/sizeof(CK_ATTRIBUTE));
	ulUnwrappedValueLen = valueTemplate[0].ulValueLen;
}

#endif

static gboolean
sw_get_challenge(keyagent_apimodule_get_challenge_details *details, void *dummy, GError **err)
{
    CK_RV				rv					= CKR_GENERAL_ERROR;
    gboolean			result				= FALSE;
	apimodule_uri_data *data 				= NULL;
    apimodule_token *atoken 				= NULL;

    if (!details || !err || !details->module_data) {
        k_set_error(err, -1, "Input parameters are invalid!");
        goto end;
	}

	data = (apimodule_uri_data *)details->module_data;

    if (!data->token_label) {
        k_set_error(err, -1, "Input parameters are invalid!");
        goto end;
	}

    atoken = lookup_apimodule_token(data->token_label->str);

    if (!atoken) {
        k_set_error(err, -1, "Input parameters are invalid!");
        goto end;
	}

#define MODULUS_INDEX	0
#define EXPONENT_INDEX	1

    do {

        rv = generate_rsa_keypair(atoken, PKCS11_APIMODULE_QUOTELABEL, PKCS11_APIMODULE_QUOTEID);
		if (rv != CKR_OK) {
    		k_set_error(err, -1, "failed to login on token");
			break;
		}

#ifdef TESTING
		rsaWrapUnwrap(CKM_RSA_PKCS,atoken->session,
    		atoken->publickey_challenge_handle, 
    		atoken->privatekey_challenge_handle);
#endif

    	CK_ULONG obj_bits = 0;
    	CK_ATTRIBUTE attribs[] = {
        	{ CKA_MODULUS, NULL_PTR, 0 },
        	{ CKA_PUBLIC_EXPONENT, NULL_PTR, 0 },
        	{ CKA_MODULUS_BITS, &obj_bits, sizeof(obj_bits) }
    	};

    	// Get length
    	rv = func_list->C_GetAttributeValue(atoken->session, atoken->publickey_challenge_handle, &attribs[0], 2);
		if (rv != CKR_OK) {
    		k_set_error(err, -1, "failed to login on token");
			break;
		}
    	attribs[MODULUS_INDEX].pValue = (CK_VOID_PTR)malloc(attribs[MODULUS_INDEX].ulValueLen);
    	attribs[EXPONENT_INDEX].pValue = (CK_VOID_PTR)malloc(attribs[EXPONENT_INDEX].ulValueLen);

    	rv = func_list->C_GetAttributeValue(atoken->session, atoken->publickey_challenge_handle, &attribs[0], 3);
		if (rv != CKR_OK) {
    		k_set_error(err, -1, "failed to login on token");
    		free(attribs[MODULUS_INDEX].pValue);
    		free(attribs[EXPONENT_INDEX].pValue);
			break;
		}

		struct keyagent_sgx_quote_info quote_info = {
			.keydetails = {
                .rsa = {
                    .exponent_len = attribs[EXPONENT_INDEX].ulValueLen,
			        .modulus_len = attribs[MODULUS_INDEX].ulValueLen,
                },
            },
			.keytype = KEYAGENT_RSAKEY
		};

		atoken->challenge = k_buffer_alloc(NULL,0);
		k_buffer_append(atoken->challenge, (guint8*)&quote_info, sizeof(quote_info));
		k_buffer_append(atoken->challenge, attribs[EXPONENT_INDEX].pValue, attribs[EXPONENT_INDEX].ulValueLen);
		k_buffer_append(atoken->challenge, attribs[MODULUS_INDEX].pValue, attribs[MODULUS_INDEX].ulValueLen);

    	free(attribs[MODULUS_INDEX].pValue);
    	free(attribs[EXPONENT_INDEX].pValue);
		result = TRUE;

    } while (FALSE);
end:
    return result;
}

#ifdef TESTING
void aesWrapUnwrapGeneric(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
	CK_KEY_TYPE genKeyType = CKK_GENERIC_SECRET;
	CK_BYTE keyPtr[128];
	CK_ULONG keyLen =
		mechanismType == CKM_AES_KEY_WRAP_PAD ? 125UL : 128UL;

	CK_ATTRIBUTE attribs[] = {
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &genKeyType, sizeof(genKeyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) }, // Wrapping is allowed even on sensitive objects
		{ CKA_VALUE, keyPtr, keyLen }
	};
	CK_OBJECT_HANDLE hSecret;
	CK_RV rv;

	k_buffer_ptr iv = k_buffer_alloc(NULL, 16);
	rv = func_list->C_GenerateRandom(hSession, k_buffer_data(iv), k_buffer_length(iv));
	gint tag_size = 16;

    CK_GCM_PARAMS gcmParams =
    {
        k_buffer_data(iv),
        k_buffer_length(iv),
        k_buffer_length(iv) * 8,
		NULL,
		0,
        tag_size*8
    };

	if (mechanismType == CKM_AES_GCM) {
		mechanism.pParameter = &gcmParams;
		mechanism.ulParameterLen = sizeof(gcmParams);
	}


	rv = func_list->C_GenerateRandom(hSession, keyPtr, keyLen);

	CK_BYTE_PTR wrappedPtr = NULL_PTR;
	CK_ULONG wrappedLen = 0UL;
	CK_ULONG rndKeyLen = keyLen;
	if (mechanismType == CKM_AES_KEY_WRAP_PAD)
		rndKeyLen =  (keyLen + 7) & ~7;

	hSecret = CK_INVALID_HANDLE;
	rv = func_list->C_CreateObject(hSession, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hSecret);
	// Estimate wrapped length
	rv = func_list->C_WrapKey(hSession, &mechanism, hKey, hSecret, NULL, &wrappedLen);
	wrappedPtr = (CK_BYTE_PTR) malloc(wrappedLen);
	rv = func_list->C_WrapKey(hSession, &mechanism, hKey, hSecret, wrappedPtr, &wrappedLen);

	CK_ATTRIBUTE nattribs[] = {
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &genKeyType, sizeof(genKeyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bFalse,sizeof(bFalse) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) }
	};
	CK_OBJECT_HANDLE hNew;
	hNew = CK_INVALID_HANDLE;
	rv = func_list->C_UnwrapKey(hSession, &mechanism, hKey, wrappedPtr, wrappedLen, nattribs, sizeof(nattribs)/sizeof(CK_ATTRIBUTE), &hNew);
	free(wrappedPtr);
	wrappedPtr = NULL_PTR;
	rv = func_list->C_DestroyObject(hSession, hSecret);
}
#endif

gboolean
sw_set_wrapping_key(keyagent_apimodule_session_details *details, void *extra, GError **err)
{
    CK_OBJECT_CLASS privClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
    CK_RV rv = CKR_GENERAL_ERROR;
	CK_MECHANISM_TYPE mechanismType = CKM_RSA_PKCS_OAEP;
	//CK_MECHANISM_TYPE mechanismType = CKM_RSA_PKCS;
    CK_MECHANISM mechanism = { mechanismType, NULL, 0 };
	CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
	gboolean ret = FALSE;
	apimodule_uri_data *data = NULL;
    apimodule_token *atoken = NULL;

	do {
    	if (!details || !details->session || !err || !details->module_data) {
        	k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		data = (apimodule_uri_data *)details->module_data;

    	if (!data->token_label) {
        	k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

    	atoken = lookup_apimodule_token(data->token_label->str);

    	if (!atoken) {
        	k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		if (mechanismType == CKM_RSA_PKCS_OAEP) {
			mechanism.pParameter = &oaepParams;
			mechanism.ulParameterLen = sizeof(oaepParams);
		}

    	CK_ATTRIBUTE nPrkAttribs[] = {
        	{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
        	{ CKA_CLASS, &privClass, sizeof(privClass) },
        	{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        	{ CKA_LABEL,            (void *)PKCS11_APIMODULE_SWKLABEL,        		strlen(PKCS11_APIMODULE_SWKLABEL) },
        	{ CKA_ID,            	(void *)PKCS11_APIMODULE_SWKID,        		strlen(PKCS11_APIMODULE_SWKID) },
        	{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        	{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
        	{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
        	{ CKA_WRAP, &bTrue, sizeof(bTrue) },
			{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
        	{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    	};

		SET_TOKEN_ATTRIBUTE(nPrkAttribs, 0);

    	hPrk = CK_INVALID_HANDLE;
    	rv = func_list->C_UnwrapKey(atoken->session, &mechanism, atoken->privatekey_challenge_handle, 
			k_buffer_data(details->session), k_buffer_length(details->session), 
			nPrkAttribs, sizeof(nPrkAttribs)/sizeof(CK_ATTRIBUTE), &hPrk);

		if (rv != CKR_OK) {
        	k_set_error(err, -1, "cannot add wrapping key");
			break;
		}
		ret = TRUE;
		atoken->wrappingkey_handle = hPrk;
#ifdef TESTING
		aesWrapUnwrapGeneric(CKM_AES_KEY_WRAP, atoken->session, atoken->wrappingkey_handle);
#endif
	} while (FALSE);
	return ret;
}
