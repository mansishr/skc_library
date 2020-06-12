#define G_LOG_DOMAIN "apimodule-sw"
#include "internal.h"
#include "key-agent/stm/stm.h"

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
	CK_MECHANISM_TYPE mechanismType = CKM_AES_KEY_WRAP;
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_RV rv;
	CK_OBJECT_HANDLE hPrivateKey;
	apimodule_uri_data *uri_data = (apimodule_uri_data *)details->module_data;
	CK_OBJECT_CLASS privClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;

	CK_ATTRIBUTE nPrkAttribs[] = {
		{ CKA_TOKEN, 	&bFalse, sizeof(bFalse) },
		{ CKA_CLASS, 	&privClass, sizeof(privClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_LABEL,    uri_data->key_label->str, uri_data->key_label->len },
		{ CKA_ID,       uri_data->key_id->str, uri_data->key_id->len },
		{ CKA_PRIVATE, 	&bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, 	&bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, 	&bTrue, sizeof(bTrue) },
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
	apimodule_uri_data *uri_data = (apimodule_uri_data *)details->module_data;
	CK_RV rv;

	CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;

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

	if(!details || !details->key || !err || !details->module_data) {
		k_critical_msg("sw_load_key: invalid input parameters");
		k_set_error(err, -1, "Input parameters are invalid!");
		goto end;
	}

	data = (apimodule_uri_data *)details->module_data;

	if(!data->token_label) {
		k_critical_msg("sw_load_key: no token label provided");
		k_set_error(err, -1, "Input parameters are invalid!");
		goto end;
	}

	atoken = lookup_apimodule_token(data->token_label->str);
	if(!atoken) {
		k_critical_msg("sw_load_key: cannot find token object for token label");
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
	if(rv == CKR_OK)
		status = TRUE;
	else {
		k_critical_msg("sw_load_key: unwrap key failed: rv %lx", rv);
		k_set_error(err, -1, "unwrap key failed!");
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
	CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE rsaKeyType = CKK_RSA;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_TOKEN,    &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_CLASS,     &pubkey_class, sizeof(pubkey_class) },
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
		{ CKA_CLASS,     &privkey_class, sizeof(privkey_class) },
		{ CKA_KEY_TYPE, &rsaKeyType, sizeof(rsaKeyType) },
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

static gboolean
sw_get_challenge(keyagent_apimodule_get_challenge_details *details, void *dummy, GError **err)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	gboolean result = FALSE;
	apimodule_uri_data *data = NULL;
	apimodule_token *atoken = NULL;

	u_int32_t major_no = 1;
	u_int32_t minor_no = 0;

	if(!details || !err || !details->module_data) {
		k_critical_msg("sw_get_challenge: Invalid Input Parameters");
		k_set_error(err, -1, "Input parameters are invalid!");
		goto end;
	}

	data = (apimodule_uri_data *)details->module_data;

	if(!data->token_label) {
		k_critical_msg("sw_get_challenge: no token label provided");
		k_set_error(err, -1, "Input parameters are invalid!");
		goto end;
	}

	atoken = lookup_apimodule_token(data->token_label->str);

	if(!atoken) {
		k_critical_msg("sw_get_challenge: cannot find token object for token label");
		k_set_error(err, -1, "Input parameters are invalid!");
		goto end;
	}

#define MODULUS_INDEX	0
#define EXPONENT_INDEX	1

	do {
		rv = generate_rsa_keypair(atoken, PKCS11_APIMODULE_QUOTELABEL, PKCS11_APIMODULE_QUOTEID);
		if(rv != CKR_OK) {
			k_critical_msg("sw_get_challenge: generate rsa key pair failed: rv 0x%lx", rv);
			k_set_error(err, -1, "failed to login on token");
			break;
		}

		CK_ULONG obj_bits = 0;
		CK_ATTRIBUTE attribs[] = {
			{ CKA_MODULUS, NULL_PTR, 0 },
			{ CKA_PUBLIC_EXPONENT, NULL_PTR, 0 },
			{ CKA_MODULUS_BITS, &obj_bits, sizeof(obj_bits) }
		};

		rv = func_list->C_GetAttributeValue(atoken->session, atoken->publickey_challenge_handle, &attribs[0], 2);
		if(rv != CKR_OK) {
			k_critical_msg("sw_get_challenge: Failed to get attrib value: rv 0x%lx", rv);
			k_set_error(err, -1, "failed to login on token");
			break;
		}
		attribs[MODULUS_INDEX].pValue = (CK_VOID_PTR)malloc(attribs[MODULUS_INDEX].ulValueLen);
		attribs[EXPONENT_INDEX].pValue = (CK_VOID_PTR)malloc(attribs[EXPONENT_INDEX].ulValueLen);

		rv = func_list->C_GetAttributeValue(atoken->session, atoken->publickey_challenge_handle, &attribs[0], 3);
		if(rv != CKR_OK) {
			k_critical_msg("sw_get_challenge: Failed to get attrib value: rv 0x%lx", rv);
			k_set_error(err, -1, "failed to login on token: rv 0x%lx", rv);
			free(attribs[MODULUS_INDEX].pValue);
			free(attribs[EXPONENT_INDEX].pValue);
			break;
		}

		struct keyagent_sgx_quote_info quote_info = {
			.major_num = major_no,
			.minor_num = minor_no,
			.quote_size = 0,
			.quote_type = KEYAGENT_SW_QUOTE_TYPE,
			.keytype = KEYAGENT_RSAKEY,
			.keydetails = {
				.rsa = {
					.exponent_len = attribs[EXPONENT_INDEX].ulValueLen,
					.modulus_len = attribs[MODULUS_INDEX].ulValueLen,
				}
			},
		};

		atoken->challenge = k_buffer_alloc(NULL,0);
		k_buffer_append(atoken->challenge, (guint8*)&quote_info, sizeof(quote_info));
		k_buffer_append(atoken->challenge, attribs[EXPONENT_INDEX].pValue, attribs[EXPONENT_INDEX].ulValueLen);
		k_buffer_append(atoken->challenge, attribs[MODULUS_INDEX].pValue, attribs[MODULUS_INDEX].ulValueLen);

		free(attribs[MODULUS_INDEX].pValue);
		free(attribs[EXPONENT_INDEX].pValue);
		result = TRUE;

	}while(FALSE);
end:
	return result;
}

gboolean
sw_set_wrapping_key(keyagent_apimodule_session_details *details, void *extra, GError **err)
{
	CK_OBJECT_CLASS privClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_MECHANISM_TYPE mechanismType = CKM_RSA_PKCS_OAEP;
	CK_MECHANISM mechanism = { mechanismType, NULL, 0 };
	CK_RSA_PKCS_OAEP_PARAMS oaepParams = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
	gboolean ret = FALSE;
	apimodule_uri_data *data = NULL;
	apimodule_token *atoken = NULL;

	do {
		if(!details || !details->session || !err || !details->module_data) {
			k_critical_msg("sw_set_wrapping_key: Invalid input provided");
			k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		data = (apimodule_uri_data *)details->module_data;

		if(!data->token_label) {
			k_critical_msg("sw_set_wrapping_key: no token label provided");
			k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		atoken = lookup_apimodule_token(data->token_label->str);

		if(!atoken) {
			k_critical_msg("sw_set_wrapping_key: Cannot find token object for token label");
			k_set_error(err, -1, "Input parameters are invalid!");
			break;
		}

		if(mechanismType == CKM_RSA_PKCS_OAEP) {
			mechanism.pParameter = &oaepParams;
			mechanism.ulParameterLen = sizeof(oaepParams);
		}

		CK_ATTRIBUTE nPrkAttribs[] = {
			{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
			{ CKA_CLASS, &privClass, sizeof(privClass) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_LABEL, (void *)PKCS11_APIMODULE_SWKLABEL, strlen(PKCS11_APIMODULE_SWKLABEL) },
			{ CKA_ID, (void *)PKCS11_APIMODULE_SWKID, strlen(PKCS11_APIMODULE_SWKID) },
			{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
			{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
			{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
			{ CKA_WRAP, &bTrue, sizeof(bTrue) },
			{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
			{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
		};

		SET_TOKEN_ATTRIBUTE(nPrkAttribs, 0);

		hPrk = CK_INVALID_HANDLE;
		rv = func_list->C_UnwrapKey(atoken->session, &mechanism, atoken->privatekey_challenge_handle,
			k_buffer_data(details->session), k_buffer_length(details->session),
			nPrkAttribs, sizeof(nPrkAttribs)/sizeof(CK_ATTRIBUTE), &hPrk);

		if(rv != CKR_OK) {
			k_critical_msg("sw_set_wrapping_key: Failed to unwrap rsa key: rv 0x%lx", rv);
			k_set_error(err, -1, "Failed to unwrap rsa key");
			break;
		}
		ret = TRUE;
		atoken->wrappingkey_handle = hPrk;
	}while(FALSE);
	return ret;
}
