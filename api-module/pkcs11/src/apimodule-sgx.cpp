#define G_LOG_DOMAIN "apimodule-sgx"
#include "config.h"
#include "k_errors.h"
#include "internal.h"

#include "key-agent/key_agent.h"
#include "key-agent/types.h"

#include <p11-sgx/Constants.h>

#define CKM_EXPORT_QUOTE_RSA_PUBLIC_KEY   0x0000210FUL
typedef struct CK_QUOTE_RSA_PUBLIC_KEY_PARAMS {
    CK_BYTE_PTR       pSpid;
    CK_ULONG          ulSpidLen;
    CK_BYTE_PTR       pSigRL;
    CK_ULONG          ulSigRLLen;
    CK_ULONG          ulQuoteSignatureType;
} CK_QUOTE_RSA_PUBLIC_KEY_PARAMS;

typedef CK_QUOTE_RSA_PUBLIC_KEY_PARAMS * CK_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR;

typedef struct CK_RSA_PUBLIC_KEY_PARAMS {
    CK_ULONG ulExponentLen;
    CK_ULONG ulModulusLen;
} CK_RSA_PUBLIC_KEY_PARAMS;

typedef CK_RSA_PUBLIC_KEY_PARAMS * CK_RSA_PUBLIC_KEY_PARAMS_PTR;

static gboolean sgx_get_challenge(keyagent_apimodule_get_challenge_details *, void *, GError **err);
static gboolean sgx_set_wrapping_key(keyagent_apimodule_session_details *, void *, GError **err);
static gboolean sgx_load_key(keyagent_apimodule_loadkey_details *, void *, GError **err);

keyagent_apimodule_ops _sgx_apimodule_ops = {
    .load_key = sgx_load_key,
    .get_challenge = sgx_get_challenge,
    .set_wrapping_key = sgx_set_wrapping_key
};

keyagent_apimodule_ops *sgx_apimodule_ops = &_sgx_apimodule_ops;

CK_RV
sgx_unwrap_symmeric_key(keyagent_apimodule_loadkey_details *details, apimodule_token *atoken)
{
	CK_MECHANISM_TYPE mechanismType = CKM_AES_GCM;
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
        //{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };

    SET_TOKEN_ATTRIBUTE(nPrkAttribs, 0);

    hPrivateKey = CK_INVALID_HANDLE;
    rv = func_list->C_UnwrapKey(atoken->session, &mechanism, atoken->wrappingkey_handle, 
		k_buffer_data(details->key), k_buffer_length(details->key), 
		nPrkAttribs, sizeof(nPrkAttribs)/sizeof(CK_ATTRIBUTE), &hPrivateKey);


	return rv;
}

static gboolean 
sgx_load_key(keyagent_apimodule_loadkey_details *details, void *extra, GError **err)
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
		rv = sgx_unwrap_symmeric_key(details, atoken);
		break;
	default:
		rv = CKR_ARGUMENTS_BAD;  
		break;
	}
    if (rv == CKR_OK)
        status = TRUE;
	else {
		k_debug_msg("error unwrapping key");
       	k_set_error(err, -1, "cannot load key");
	}
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

gboolean sgx_get_challenge(keyagent_apimodule_get_challenge_details *details, void *request, GError **err)
{
    CK_RV				rv					= CKR_GENERAL_ERROR;
    gboolean			result				= FALSE;
	CK_MECHANISM_TYPE	mechanismType		= CKM_EXPORT_QUOTE_RSA_PUBLIC_KEY;
    CK_MECHANISM		mechanism			= { mechanismType, NULL, 0 };
    CK_RSA_PUBLIC_KEY_PARAMS* rsaPublicKeyParams = NULL;
    CK_MECHANISM_PTR    pMechanism  		= &mechanism;
    CK_ULONG			quote_len	        = 0UL;
    k_buffer_ptr		quote_details		= NULL;
    struct keyagent_sgx_challenge_request   *challenge_request = (struct keyagent_sgx_challenge_request *)request;
    CK_ULONG            signatureType       = UNLINKABLE_SIGNATURE;
	apimodule_uri_data *data 				= NULL;
    apimodule_token *atoken 				= NULL;
	CK_BYTE_PTR spid						= NULL;
	CK_ULONG spid_len						= 0;
	CK_BYTE_PTR sigrl						= NULL;
	CK_ULONG sigrl_len						= 0;

    if (!details || !request || !err || !details->module_data) {
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

    atoken = lookup_apimodule_token(data->token_label->str);

    if (challenge_request) {
        signatureType = (challenge_request->linkable ? LINKABLE_SIGNATURE : UNLINKABLE_SIGNATURE);
		spid = (CK_BYTE_PTR)challenge_request->spid;
		spid_len = (spid ? strlen(challenge_request->spid) : 0);
		sigrl = (CK_BYTE_PTR)challenge_request->sigrl;
		sigrl_len = (sigrl ? strlen(challenge_request->sigrl) : 0);
	}

    do {

    	CK_QUOTE_RSA_PUBLIC_KEY_PARAMS quoteRSAParams = {
			spid,
			spid_len,
        	sigrl,
        	sigrl_len,
        	signatureType
    	};

        rv = generate_rsa_keypair(atoken, PKCS11_APIMODULE_QUOTELABEL, PKCS11_APIMODULE_QUOTEID);
		if (rv != CKR_OK) {
    		k_set_error(err, -1, "failed to login on token");
			break;
		}

        pMechanism->pParameter = &quoteRSAParams;
        pMechanism->ulParameterLen = sizeof(quoteRSAParams);

        rv = func_list->C_WrapKey(atoken->session, pMechanism, (CK_OBJECT_HANDLE)NULL,
            atoken->publickey_challenge_handle,
            NULL,
            &quote_len);

        if (CKR_OK != rv) {
            k_info_msg("FAILED : C_WrapKey : failed to calc quote size!");
    		k_set_error(err, -1, "failed to calc quote size");
            break;
        }

        quote_details = k_buffer_alloc(NULL, quote_len);
        rv = func_list->C_WrapKey(atoken->session,
            pMechanism,
            (CK_OBJECT_HANDLE)NULL,
            atoken->publickey_challenge_handle,
            k_buffer_data(quote_details),
            &quote_len);

        if (CKR_OK != rv) {
            k_info_msg("FAILED : C_WrapKey : failed to get quote!");
    		k_set_error(err, -1, "failed to get quote");
            break;
        }

        rsaPublicKeyParams = (CK_RSA_PUBLIC_KEY_PARAMS*)k_buffer_data(quote_details);

		struct keyagent_sgx_quote_info quote_info = {
			.keydetails = {
                .rsa = {
                    .exponent_len = rsaPublicKeyParams->ulExponentLen,	
			        .modulus_len = rsaPublicKeyParams->ulModulusLen,
                },
            },
			.keytype = KEYAGENT_RSAKEY
		};

		atoken->challenge = k_buffer_alloc(NULL,0);
		k_buffer_append(atoken->challenge, (guint8*)&quote_info, sizeof(quote_info));
		k_buffer_append(atoken->challenge, k_buffer_data(quote_details) + sizeof(CK_RSA_PUBLIC_KEY_PARAMS), quote_len - sizeof(CK_RSA_PUBLIC_KEY_PARAMS));
		result = TRUE;
    } while (FALSE);
end:
	k_buffer_unref(quote_details);
    return result;
}

gboolean
sgx_set_wrapping_key(keyagent_apimodule_session_details *details, void *extra, GError **err)
{
    CK_OBJECT_CLASS privClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
    CK_RV rv = CKR_GENERAL_ERROR;
	CK_MECHANISM_TYPE mechanismType = CKM_RSA_PKCS;
	//CK_MECHANISM_TYPE mechanismType = CKM_RSA_PKCS_OAEP;
    CK_MECHANISM mechanism = { mechanismType, NULL, 0 };
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

    	CK_ATTRIBUTE nPrkAttribs[] = {
        	{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
        	{ CKA_CLASS, &privClass, sizeof(privClass) },
        	{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        	{ CKA_LABEL,            (void *)PKCS11_APIMODULE_SWKLABEL,        		strlen(PKCS11_APIMODULE_SWKLABEL) },
        	{ CKA_ID,            	(void *)PKCS11_APIMODULE_SWKID,        		strlen(PKCS11_APIMODULE_SWKID) },
        	{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        	{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
        	{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
        	//{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    	};

        SET_TOKEN_ATTRIBUTE(nPrkAttribs, 0);

    	hPrk = CK_INVALID_HANDLE;
    	rv = func_list->C_UnwrapKey(atoken->session, &mechanism, atoken->privatekey_challenge_handle, 
			k_buffer_data(details->session), k_buffer_length(details->session), 
			nPrkAttribs, sizeof(nPrkAttribs)/sizeof(CK_ATTRIBUTE), &hPrk);

		if (rv != CKR_OK) {
			k_debug_msg("error unwrapping wrapping key");
        	k_set_error(err, -1, "cannot add wrapping key");
			break;
		}
		ret = TRUE;
		atoken->wrappingkey_handle = hPrk;
	} while(FALSE);
	return ret;
}
