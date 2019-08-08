#define G_LOG_DOMAIN "apimodule-sgx"
#include <glib.h>
#include "config.h"
#include "k_errors.h"
#include "internal.h"

#include "key-agent/key_agent.h"
#include "key-agent/types.h"
#include "key-agent/stm/stm.h"
#include "include/k_debug.h"

#include <fstream>
#include <sstream>

#include <regex>
#include <string.h>
#include <vector>

#include <iostream>

#include <sgx_quote_3.h>


#include "p11Defines.h"

#ifdef QUOTE_DUMP
#include "sgx_quote.h"
#endif

using namespace std;
#define SGX_ECDSA_QUOTE_VERIFIABLE 5
#define REF_ECDSDA_AUTHENTICATION_DATA_SIZE 32

typedef CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS * CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS_PTR;
typedef CK_RSA_PUBLIC_KEY_PARAMS * CK_RSA_PUBLIC_KEY_PARAMS_PTR;

static gboolean sgx_get_challenge(keyagent_apimodule_get_challenge_details *, void *, GError **err);
static gboolean sgx_set_wrapping_key(keyagent_apimodule_session_details *, void *, GError **err);
static gboolean sgx_load_key(keyagent_apimodule_loadkey_details *, void *, GError **err);


keyagent_apimodule_ops _sgx_apimodule_ops = {
    .init = NULL,
    .load_uri = NULL,
    .load_key = sgx_load_key,
    .get_challenge = sgx_get_challenge,
    .set_wrapping_key = sgx_set_wrapping_key
};

keyagent_apimodule_ops *sgx_apimodule_ops = &_sgx_apimodule_ops;

CK_RV
sgx_unwrap_rsa_key(keyagent_apimodule_loadkey_details *details, apimodule_token *atoken)
{
        CK_MECHANISM_TYPE mechanismType = CKM_AES_GCM;
        CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
        apimodule_uri_data *uri_data = (apimodule_uri_data *)details->module_data;
        CK_RV rv;
        CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };

        CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
        CK_KEY_TYPE keyType = CKK_RSA;

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
                { CKA_TOKEN, &bFalse, sizeof(bFalse) },
                { CKA_CLASS, &privateClass, sizeof(privateClass) },
                { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        	{ CKA_LABEL,    uri_data->key_label->str, uri_data->key_label->len },
        	{ CKA_ID,       uri_data->key_id->str, uri_data->key_id->len },
                { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
                { CKA_DECRYPT, &bTrue, sizeof(bTrue) },
                { CKA_SIGN, &bTrue,sizeof(bTrue) },
                //{ CKA_VERIFY, &bTrue,sizeof(bTrue) },
                { CKA_UNWRAP, &bTrue, sizeof(bTrue) },
                //{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
                //{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
        };

        SET_TOKEN_ATTRIBUTE(nPrkAttribs, 0);


        hPrk = CK_INVALID_HANDLE;
        rv = func_list->C_UnwrapKey(atoken->session, &mechanism, atoken->wrappingkey_handle,
                k_buffer_data(details->key), k_buffer_length(details->key),
                nPrkAttribs, sizeof(nPrkAttribs)/sizeof(CK_ATTRIBUTE), &hPrk);
        return rv;
}


CK_RV
sgx_unwrap_symmeric_key(keyagent_apimodule_loadkey_details *details, apimodule_token *atoken)
{
  
    CK_MECHANISM_TYPE mechanismType = CKM_AES_GCM;
    CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
    CK_RV rv;
    CK_OBJECT_HANDLE hPrivateKey;
    gboolean ret = FALSE;
    apimodule_uri_data *uri_data   = (apimodule_uri_data *)details->module_data;
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
 	{ CKA_ENCRYPT,  &bTrue, sizeof(bTrue) }, 
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
	case KEYAGENT_RSAKEY:
		rv = sgx_unwrap_rsa_key(details, atoken);
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
	CK_RV rv					= CKR_GENERAL_ERROR;
	gboolean result				= FALSE;
	CK_RSA_PUBLIC_KEY_PARAMS* rsaPublicKeyParams  = NULL;
	CK_ULONG	quote_len	        	= 0UL;
	k_buffer_ptr quote_details			= NULL;
	k_buffer_ptr cert_information        		= NULL;

	struct keyagent_sgx_challenge_request   *challenge_request 
		= (struct keyagent_sgx_challenge_request *)request;
	CK_ULONG  signatureType       		= UNLINKABLE_SIGNATURE;
	apimodule_uri_data *data 			= NULL;
	apimodule_token *atoken 			= NULL;
	CK_BYTE_PTR spid				= NULL;
	CK_ULONG spid_len				= 0;
	CK_BYTE_PTR sigrl				= NULL;
	CK_ULONG sigrl_len				= 0;
	CK_ULONG launch_policy				= 0;
	CK_MECHANISM_TYPE   mechanismType		= 0;
	gint actual_quote_size				= 0;
	gint full_key_size				= 0;
    CK_BYTE spid_arr[DEFAULT_SPID_LEN/2]	= {0};
	CK_MECHANISM mechanism				= {0};
	CK_MECHANISM_PTR   pMechanism  			= NULL;
	u_int32_t major_no				= 1;
	u_int32_t minor_no				= 0;
    CK_EPID_QUOTE_RSA_PUBLIC_KEY_PARAMS 
				quoteRSAParams  = {0};


	if (strcmp(challenge_request->attestationType,"EPID") == 0) {
		mechanismType           	= CKM_EXPORT_EPID_QUOTE_RSA_PUBLIC_KEY;
	} else if (strcmp(challenge_request->attestationType,"ECDSA") == 0) {
		mechanismType           	= CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY;
	} 

	if (!details || !request || !err || !details->module_data || !mechanismType) {
		k_set_error(err, -1, "Input parameters are invalid!");
		goto end;
	}

	mechanism					= { mechanismType, NULL, 0 };
	pMechanism  					= &mechanism;
	data 						= (apimodule_uri_data *)details->module_data;

	if (!data->token_label) {
		k_set_error(err, -1, "Input parameters are invalid!");
		goto end;
	}

	atoken 					= lookup_apimodule_token(data->token_label->str);
	if (!atoken) {
		k_set_error(err, -1, "Input parameters are invalid!");
		goto end;
	}

	if (strcmp(challenge_request->attestationType,"EPID") == 0) {
        k_debug_msg("EPID request "); 

		if( challenge_request && strlen(challenge_request->spid) != DEFAULT_SPID_LEN )
		{
			k_critical_msg("Invalid SPID length:%s:%d!, expected len %d\n",challenge_request->spid,  
					strlen(challenge_request->spid), DEFAULT_SPID_LEN);
			k_set_error(err, -1, "Invalid SPID length:%d!, expected len %d\n", strlen(challenge_request->spid), DEFAULT_SPID_LEN);
			goto end;
		}

		result					= convert_hexstring_to_byte_array( spid_arr,  
				challenge_request->spid, 
				strlen(challenge_request->spid)/2);
		if( result != TRUE)
		{
			k_critical_msg("Byte error convert error!");
			k_set_error(err, -1, "Byte error convert error!");
			goto end;
		}

		signatureType 				= (challenge_request->linkable ? LINKABLE_SIGNATURE : UNLINKABLE_SIGNATURE);
		spid 					= (CK_BYTE_PTR)spid_arr;
		spid_len 				= (spid ? (strlen(challenge_request->spid)/2) : 0);
		sigrl 					= (CK_BYTE_PTR)challenge_request->sigrl;
		sigrl_len 				= (sigrl ? strlen(challenge_request->sigrl)/2 : 0);


	k_debug_msg("Sigrl:%s and sigrl len:%d, sigtype:%d, spid_len:%d", sigrl, sigrl_len, signatureType, spid_len);
	quoteRSAParams.pSpid 			= spid;
	quoteRSAParams.ulSpidLen 		= spid_len;
	quoteRSAParams.pSigRL 			= sigrl;
	quoteRSAParams.ulSigRLLen 		= sigrl_len;
	quoteRSAParams.ulQuoteSignatureType 	= signatureType;
		pMechanism->pParameter 			= &quoteRSAParams;
		pMechanism->ulParameterLen 		= sizeof(quoteRSAParams);

	} else if (strcmp(challenge_request->attestationType,"ECDSA") == 0) {
		k_debug_msg("ECDSA request");
		launch_policy 			= (CK_ULONG)challenge_request->launch_policy;
		static CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS 
				quoteRSAParams  = {
						launch_policy
				};
		pMechanism->pParameter 		= &quoteRSAParams;
		pMechanism->ulParameterLen 		= sizeof(quoteRSAParams);
	} else {
			k_debug_msg("incorrect attestaion type");
			k_set_error(err, -1, "incorrect attestaion type!");
			goto end;
	}

	do {
			rv 					= generate_rsa_keypair(
							atoken, 
							PKCS11_APIMODULE_QUOTELABEL, 
							PKCS11_APIMODULE_QUOTEID);
			if (rv != CKR_OK) {
				k_set_error(err, -1, "failed to login on token");
				break;
			}

			rv 					= func_list->C_WrapKey(atoken->session, pMechanism, (CK_OBJECT_HANDLE)NULL,
							atoken->publickey_challenge_handle,NULL,&quote_len);

			if (CKR_OK != rv) {
					k_info_msg("FAILED : C_WrapKey : failed to calc quote size!");
					k_set_error(err, -1, "failed to calc quote size");
					break;
			}

			quote_details 				= k_buffer_alloc(NULL, quote_len);
			rv 					= func_list->C_WrapKey(atoken->session,
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

			rsaPublicKeyParams 			= (CK_RSA_PUBLIC_KEY_PARAMS*)k_buffer_data(quote_details);

			if( mechanismType == CKM_EXPORT_EPID_QUOTE_RSA_PUBLIC_KEY){
					full_key_size 				= sizeof(CK_RSA_PUBLIC_KEY_PARAMS)+
							(rsaPublicKeyParams->ulExponentLen + rsaPublicKeyParams->ulModulusLen);
					actual_quote_size 			= quote_len - full_key_size;
					struct keyagent_sgx_quote_info quote_info   = {0};
					quote_info.major_num			= major_no;
					quote_info.minor_num			= minor_no;
					quote_info.quote_size			= actual_quote_size;
					quote_info.quote_type		= KEYAGENT_SGX_QUOTE_TYPE_EPID;
					quote_info.keytype			= KEYAGENT_RSAKEY;
					quote_info.keydetails.rsa.exponent_len  = rsaPublicKeyParams->ulExponentLen;
					quote_info.keydetails.rsa.modulus_len  	= rsaPublicKeyParams->ulModulusLen;

#ifdef QUOTE_DUMP
					const gchar *quote_file			= "/tmp/quote_app.txt";
					sgx_quote_t *sgx_quote			= reinterpret_cast<sgx_quote_t*>(k_buffer_data(quote_details)+full_key_size);


			const gchar *encoded_sgx_quote 		= g_base64_encode((const guchar*) (sgx_quote), actual_quote_size);
			result 					= g_file_set_contents (quote_file,
							encoded_sgx_quote,
							strlen(encoded_sgx_quote),
							err);
			if( result == TRUE )
			{
					k_debug_msg("Quote Len:%d\nquote:%s\nquote_len:%d\n", 
									actual_quote_size,  encoded_sgx_quote, strlen(encoded_sgx_quote));
			}else{
					k_critical_msg("Error in quote write to file\n");

			}
#endif

		g_stpcpy( quote_info.quote_details.epid_quote_details.spid, challenge_request->spid);
		atoken->challenge 			= k_buffer_alloc(NULL,0);
		k_buffer_append(atoken->challenge, (guint8*)&quote_info, sizeof(quote_info));
	} else if( mechanismType == CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY) {

		u_int32_t public_key_size = rsaPublicKeyParams->ulExponentLen + rsaPublicKeyParams->ulModulusLen;

		sgx_ql_certification_data_t *cert_buffer = (sgx_ql_certification_data_t*)(k_buffer_data(quote_details) +sizeof(CK_RSA_PUBLIC_KEY_PARAMS) + public_key_size+sizeof(sgx_quote3_t)+sizeof(sgx_ql_ecdsa_sig_data_t) + sizeof(sgx_ql_auth_data_t) + REF_ECDSDA_AUTHENTICATION_DATA_SIZE);
		///A Hexadevimal value 05 00 means that quote is verifiable.
		if (cert_buffer->cert_key_type != SGX_ECDSA_QUOTE_VERIFIABLE) {
			k_info_msg("pck certficate missing from quote!!!!");
			k_set_error(err, -1, "failed to get verifiable quote");
			break;
		}
		uint32_t certSize = cert_buffer->size;
		cert_information = k_buffer_alloc(NULL, certSize);
		memcpy(k_buffer_data(cert_information), (unsigned char*)(cert_buffer->certification_data), certSize);
		///Fetch PCK Certoficate from PCK Cert chain. PCK is the 1st certificate in the chain.
		///Hence we will fetch it by getting the position of the ending of PCK and copying it.
		std::string pckCert;
		std::size_t pckPos1, pckPos2;
		const char* certificate_pattern = "-----BEGIN CERTIFICATE-----";
		///Whole PCK chain from which PCK will be fetched.
		std::string certificate_str((const char*)(k_buffer_data(cert_information)));
		pckPos1 = certificate_str.find(certificate_pattern);
		if (pckPos1!=std::string::npos) {
			pckPos2 = certificate_str.find(certificate_pattern, pckPos1 + 1);
			if (pckPos2!=std::string::npos) {
				pckCert = certificate_str.substr(pckPos1, pckPos2);
			} else {
				k_set_error(err, -1, "pck certificate couldn't be fetched");
				break;
			}
		} else {
			k_set_error(err, -1, "pck certificate couldn't be fetched");
			break;
		}
		const int pckCertSize = pckPos2;

		struct keyagent_sgx_quote_info quote_info = {
			.major_num = major_no,
			.minor_num = minor_no,
			.quote_size = quote_len - sizeof(CK_RSA_PUBLIC_KEY_PARAMS),
			.quote_type = KEYAGENT_SGX_QUOTE_TYPE_ECDSA,
			.keytype = KEYAGENT_RSAKEY,
			.keydetails = {
				.rsa = {
					.exponent_len = rsaPublicKeyParams->ulExponentLen,	
					.modulus_len = rsaPublicKeyParams->ulModulusLen,
				},
			},
			.quote_details = {
				.ecdsa_quote_details = {
					.pckCert_size =  pckCertSize,
				},
			}
		};

		k_debug_msg("pckCert: %s", pckCert.c_str());
		k_debug_msg("pckCert size: %d", pckCertSize);
		k_debug_msg("quote_size: %d", quote_info.quote_size);
		atoken->challenge = k_buffer_alloc(NULL,0);
		k_buffer_append(atoken->challenge, (guint8*)&quote_info, sizeof(quote_info));
		k_buffer_append(atoken->challenge,(char *)( pckCert.c_str()), pckCertSize);
	}else{
    		k_set_error(err, -1, "Invalid quote type\n");
			break;
	}

	k_buffer_append(atoken->challenge, k_buffer_data(quote_details) + sizeof(CK_RSA_PUBLIC_KEY_PARAMS), 
									quote_len - sizeof(CK_RSA_PUBLIC_KEY_PARAMS));
	result = TRUE;
    } while (FALSE);

end:
	k_buffer_unref(quote_details);
	if (cert_information) k_buffer_unref(cert_information);
	return result;
}

gboolean
sgx_set_wrapping_key(keyagent_apimodule_session_details *details, void *extra, GError **err)
{
    CK_OBJECT_CLASS privClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
    CK_RV rv = CKR_GENERAL_ERROR;
    //CK_MECHANISM_TYPE mechanismType = CKM_RSA_PKCS;
    CK_MECHANISM_TYPE mechanismType = CKM_RSA_PKCS_OAEP;
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
			{ CKA_LABEL, (void *)PKCS11_APIMODULE_SWKLABEL, strlen(PKCS11_APIMODULE_SWKLABEL) },
			{ CKA_ID,  (void *)PKCS11_APIMODULE_SWKID, strlen(PKCS11_APIMODULE_SWKID) },
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
