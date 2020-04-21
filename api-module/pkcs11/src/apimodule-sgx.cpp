#define G_LOG_DOMAIN "apimodule-sgx"
#include <sgx_quote_3.h>
#include "internal.h"
#include "key-agent/stm/stm.h"
#include "include/k_debug.h"
#include "QuoteGeneration.h"

using namespace std;
#define SGX_ECDSA_QUOTE_VERIFIABLE 5
#define REF_ECDSDA_AUTHENTICATION_DATA_SIZE 32

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
		details->tag_size * 8
	};

	if(mechanismType == CKM_AES_GCM) {
		mechanism.pParameter = &gcmParams;
		mechanism.ulParameterLen = sizeof(gcmParams);
	}

        CK_ATTRIBUTE nPrkAttribs[] = {
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_CLASS, &privateClass, sizeof(privateClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_LABEL, uri_data->key_label->str, uri_data->key_label->len },
		{ CKA_ID, uri_data->key_id->str, uri_data->key_id->len },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue,sizeof(bTrue) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
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
	apimodule_uri_data *uri_data = (apimodule_uri_data *)details->module_data;
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

	if(mechanismType == CKM_AES_GCM) {
		mechanism.pParameter = &gcmParams;
		mechanism.ulParameterLen = sizeof(gcmParams);
	}

	CK_ATTRIBUTE nPrkAttribs[] = {
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_CLASS, &privClass, sizeof(privClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_LABEL, uri_data->key_label->str, uri_data->key_label->len },
		{ CKA_ID, uri_data->key_id->str, uri_data->key_id->len },
		{ CKA_PRIVATE, 	&bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, 	&bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT,  &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, 	&bTrue, sizeof(bTrue) },
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

	if(!details || !details->key || !err || !details->module_data) {
		k_critical_msg("Invalid Input Parameters");
		k_set_error(err, -1, "Input parameters are invalid!");
		goto end;
	}
	data = (apimodule_uri_data *)details->module_data;

	if(!data->token_label) {
		k_critical_msg("no token label provided");
		k_set_error(err, -1, "Input parameters are invalid!");
		goto end;
	}

	atoken = lookup_apimodule_token(data->token_label->str);

	if(!atoken) {
		k_critical_msg("cannot find token object for token label");
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
	if(rv == CKR_OK)
		status = TRUE;
	else {
		k_critical_msg("error unwrapping key: rv %lx", rv);
		k_set_error(err, -1, "cannot load key");
	}
end:
	return status;
}

static CK_RV
generate_rsa_keypair(apimodule_token *atoken, const char *label, const char *id)
{
	CK_BBOOL bTokenPuk = CK_FALSE;
	CK_BBOOL bTokenPrk = CK_FALSE;
	CK_BBOOL bPrivatePuk = CK_TRUE;
	CK_BBOOL bPrivatePrk = CK_TRUE;

	CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ULONG bits = 2048;
	CK_BYTE pubExp[] = {0x01, 0x00, 0x01};
	CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE rsaKeyType = CKK_RSA;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_TOKEN,    &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_CLASS,    &pubkey_class, sizeof(pubkey_class) },
		{ CKA_KEY_TYPE, &rsaKeyType, sizeof(rsaKeyType) },
		{ CKA_LABEL,    (void *)label, strlen(label) },
		{ CKA_ID,       (void *)id, strlen(id) },
		{ CKA_PRIVATE,  &bPrivatePuk, sizeof(bPrivatePuk) },
		{ CKA_ENCRYPT,  &bTrue, sizeof(bTrue) },
		{ CKA_VERIFY,   &bTrue, sizeof(bTrue) },
		{ CKA_WRAP,     &bTrue, sizeof(bTrue) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_TOKEN,    &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_CLASS,    &privkey_class, sizeof(privkey_class) },
		{ CKA_KEY_TYPE, &rsaKeyType, sizeof(rsaKeyType)   },
		{ CKA_LABEL,    (void *)label, strlen(label) },
		{ CKA_ID,       (void *)id, strlen(id) },
		{ CKA_PRIVATE,  &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_DECRYPT,  &bTrue, sizeof(bTrue) },
		{ CKA_SIGN,     &bTrue, sizeof(bTrue) },
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
	CK_RV rv = CKR_GENERAL_ERROR;
	gboolean result	= FALSE;
	CK_RSA_PUBLIC_KEY_PARAMS* rsaPublicKeyParams = NULL;
	CK_ULONG quote_len = 0UL;
	k_buffer_ptr quote_details = NULL;
	k_buffer_ptr cert_information = NULL;

	struct keyagent_sgx_challenge_request *challenge_request
		= (struct keyagent_sgx_challenge_request *)request;
	apimodule_uri_data *data = NULL;
	apimodule_token *atoken = NULL;
	CK_LONG launch_policy = 0;
	CK_MECHANISM_TYPE mechanismType	= 0;
	CK_MECHANISM mechanism = {0};
	CK_MECHANISM_PTR pMechanism = NULL;
	u_int32_t major_no = 1;
	u_int32_t minor_no = 0;

	if(strcmp(challenge_request->attestationType,"ECDSA") == 0) {
		mechanismType = CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY;
	}

	if(!details || !request || !err || !details->module_data || !mechanismType) {
		k_critical_msg("Invalid Input Parameters");
		k_set_error(err, -1, "Input parameters are invalid!");
		goto end;
	}

	mechanism = { mechanismType, NULL, 0 };
	pMechanism = &mechanism;
	data = (apimodule_uri_data *)details->module_data;

	if(!data->token_label) {
		k_critical_msg("token label missing");
		k_set_error(err, -1, "Input parameters are invalid!");
		goto end;
	}

	atoken = lookup_apimodule_token(data->token_label->str);
	if(!atoken) {
		k_critical_msg("cannot fetch token object based on token label");
		k_set_error(err, -1, "Input parameters are invalid!");
		goto end;
	}

	if(strcmp(challenge_request->attestationType,"ECDSA") == 0) {
		launch_policy = challenge_request->launch_policy;
		static CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS
			quoteRSAParams  = {
				launch_policy
			};
		pMechanism->pParameter = &quoteRSAParams;
		pMechanism->ulParameterLen = sizeof(quoteRSAParams);
	} else {
		k_critical_msg("incorrect attestaion type");
		k_set_error(err, -1, "incorrect attestaion type!");
		goto end;
	}

	do {
		rv = generate_rsa_keypair(atoken, PKCS11_APIMODULE_QUOTELABEL,
					PKCS11_APIMODULE_QUOTEID);
		if(rv != CKR_OK) {
			k_critical_msg("Generate RSA Key Pair failed: rv %lx", rv);
			k_set_error(err, -1, "failed to login on token");
			break;
		}

		rv = func_list->C_WrapKey(atoken->session, pMechanism, (CK_OBJECT_HANDLE)NULL,
				atoken->publickey_challenge_handle,NULL,&quote_len);
		if(CKR_OK != rv) {
			k_critical_msg("FAILED : C_WrapKey : failed to get quote size from enclave!: rv %lx", rv);
			k_set_error(err, -1, "failed to get quote size");
			break;
		}
		quote_details = k_buffer_alloc(NULL, quote_len);
		rv = func_list->C_WrapKey(atoken->session, pMechanism, (CK_OBJECT_HANDLE)NULL,
					atoken->publickey_challenge_handle,
					k_buffer_data(quote_details), &quote_len);

		if(CKR_OK != rv) {
			k_critical_msg("FAILED : C_WrapKey : failed to get ECDSA quote from enclave!: rv %lx", rv);
			k_set_error(err, -1, "failed to get quote");
			break;
		}

		rsaPublicKeyParams = (CK_RSA_PUBLIC_KEY_PARAMS*)k_buffer_data(quote_details);

		if(mechanismType == CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY) {
			u_int32_t public_key_size = rsaPublicKeyParams->ulExponentLen + rsaPublicKeyParams->ulModulusLen;

			sgx_ql_certification_data_t *cert_buffer = (sgx_ql_certification_data_t*)(k_buffer_data(quote_details)
					+ sizeof(CK_RSA_PUBLIC_KEY_PARAMS) + public_key_size + sizeof(sgx_quote3_t)
					+ sizeof(sgx_ql_ecdsa_sig_data_t) + sizeof(sgx_ql_auth_data_t)
					+ REF_ECDSDA_AUTHENTICATION_DATA_SIZE);
			///A Hexadevimal value 05 00 denotes certificate type
			if(cert_buffer->cert_key_type != SGX_ECDSA_QUOTE_VERIFIABLE) {
				k_critical_msg("pck certficate missing from quote!!!!");
				k_set_error(err, -1, "quote is generated but cannot be verified");
				break;
			}
			uint32_t certSize = cert_buffer->size;
			cert_information = k_buffer_alloc(NULL, certSize);
			memcpy(k_buffer_data(cert_information), (unsigned char*)(cert_buffer->certification_data), certSize);
			// Fetch PCK Certificate from PCK Cert chain. PCK is the 1st certificate in the chain.
			// Hence we will fetch it by getting the position of the ending of PCK and copying it.
			std::string pckCert;
			std::size_t pckPos1, pckPos2;
			const char* certificate_pattern = "-----BEGIN CERTIFICATE-----";
			// Whole PCK chain in quote from which PCK cert will be fetched.
			std::string certificate_str((const char*)(k_buffer_data(cert_information)));
			pckPos1 = certificate_str.find(certificate_pattern);
			if(pckPos1 != std::string::npos) {
				pckPos2 = certificate_str.find(certificate_pattern, pckPos1 + 1);
				if(pckPos2 != std::string::npos) {
					pckCert = certificate_str.substr(pckPos1, pckPos2);
				} else {
					k_critical_msg("pck certficate could not be fetched");
					k_set_error(err, -1, "pck certificate couldn't be fetched");
					break;
				}
			} else {
				k_critical_msg("pck certficate could not be fetched");
				k_set_error(err, -1, "pck certificate couldn't be fetched");
				break;
			}
			const uint pckCertSize = pckPos2;

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

			atoken->challenge = k_buffer_alloc(NULL,0);
			k_buffer_append(atoken->challenge, (guint8*)&quote_info, sizeof(quote_info));
			k_buffer_append(atoken->challenge,(char *)(pckCert.c_str()), pckCertSize);
		} else {
			k_critical_msg("Invalid ECDSA Key Quote");
			k_set_error(err, -1, "Invalid quote type\n");
			break;
		}

		k_buffer_append(atoken->challenge, k_buffer_data(quote_details) + sizeof(CK_RSA_PUBLIC_KEY_PARAMS),
				quote_len - sizeof(CK_RSA_PUBLIC_KEY_PARAMS));
		result = TRUE;
	}while(FALSE);

end:
	k_buffer_unref(quote_details);
	if(cert_information)
		k_buffer_unref(cert_information);
	return result;
}

gboolean
sgx_set_wrapping_key(keyagent_apimodule_session_details *details, void *extra, GError **err)
{
	CK_OBJECT_CLASS privClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_MECHANISM_TYPE mechanismType = CKM_RSA_PKCS_OAEP;
	CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
	CK_MECHANISM mechanism = { mechanismType, NULL, 0 };
	mechanism.pParameter = &oaepParams;
	mechanism.ulParameterLen = sizeof(oaepParams);

	gboolean ret = FALSE;
	apimodule_uri_data *data = NULL;
	apimodule_token *atoken = NULL;

	do {
		if(!details || !details->session || !err || !details->module_data) {
			k_critical_msg("Invalid Input Provided");
			k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		data = (apimodule_uri_data *)details->module_data;

		if(!data->token_label) {
			k_critical_msg("No token label provided");
			k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		atoken = lookup_apimodule_token(data->token_label->str);

		if(!atoken) {
			k_critical_msg("Cannot find token object for token label");
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
		};

		SET_TOKEN_ATTRIBUTE(nPrkAttribs, 0);

		hPrk = CK_INVALID_HANDLE;
		rv = func_list->C_UnwrapKey(atoken->session, &mechanism, atoken->privatekey_challenge_handle,
				k_buffer_data(details->session), k_buffer_length(details->session),
				nPrkAttribs, sizeof(nPrkAttribs)/sizeof(CK_ATTRIBUTE), &hPrk);

		if(rv != CKR_OK) {
			k_critical_msg("error unwrapping wrapping key : rv : %lx ", rv);
			k_set_error(err, -1, "cannot add wrapping key");
			break;
		}
		ret = TRUE;
		atoken->wrappingkey_handle = hPrk;
	} while(FALSE);
	return ret;
}
