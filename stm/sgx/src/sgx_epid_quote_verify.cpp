#define G_LOG_DOMAIN "SGX-EPID-ATTESTATION"

#include "sgx_uae_service.h"
#include "k_types.h"
#include "k_errors.h"
#include "curl/curl.h"
#include "sgx_epid_quote_verify.h"

using namespace std;

namespace stmsgx_epid_ssl_data{
	gchar *ias_base_url;
	gchar *ias_version;
	gchar *ias_cacert;
	gchar *ias_sub_key;
	gchar *cacert;
	gchar *proxy;
	gboolean verify;
        X509_STORE *store;
}

gboolean set_quote_verify_ssl_options(keyagent_ssl_opts *ssl_opts);

void DLL_LOCAL
print_hexstring (FILE *fp, const void *vsrc, size_t len)
{
        const unsigned char *sp= (const unsigned char *) vsrc;
        size_t i;
        for(i= 0; i< len; ++i) {
                fprintf(fp, "%02x", sp[i]);
        }
}

std::string DLL_LOCAL
get_json_value(Json::Value value, const char *key)
{
	char exceptstr[64]                                  = "Error in parsing json key:";
	if( !value.isMember(key))
	{
	    strcat(exceptstr, key);
		    throw std::runtime_error(exceptstr);
	}
	return value[key].asString();
}

void DLL_LOCAL
json_print(Json::Value &val)
{
	switch (val.type()) {
		case Json::nullValue: k_debug_msg("null"); break;
		case Json::intValue: k_debug_msg("int %d", val.asLargestInt()); break;
		case Json::uintValue: k_debug_msg("uint %d", val.asLargestUInt()); break;
		case Json::realValue: k_debug_msg("real %f",  val.asDouble()); break;
		case Json::stringValue: k_debug_msg("string %s", val.asString().c_str()); break;
		case Json::booleanValue: k_debug_msg("boolean %d", val.asBool()); break;
		case Json::arrayValue: k_debug_msg("array of length %d", val.size()); break;
		case Json::objectValue: k_debug_msg("object of length %d", val.size()); break;
		default: k_debug_msg("wrong type"); break;
    	}
}

static Json::Value DLL_LOCAL 
parse_data(k_buffer_ptr data, gboolean debug)
{
     	Json::Value jsonData;
     	Json::Reader jsonReader;

     	if (jsonReader.parse((char *)k_buffer_data(data), (char *)(k_buffer_data(data) + k_buffer_length(data)), jsonData))
     	{
                 if (debug)
                 {
                 	k_debug_msg("JSON data received:");
                 	k_debug_msg("%s", jsonData.toStyledString().c_str());
                 }
        }
        return jsonData;
 }


gboolean DLL_PUBLIC
stmsgx_put_ias_signing_cert_to_store(char *ias_cacert_path, GError **error)
{
	X509 *cert = NULL;
	gboolean ret = FALSE;
	FILE *fp = NULL;

	OpenSSL_add_all_algorithms();
  	ERR_load_BIO_strings();
  	ERR_load_crypto_strings();

	if ((fp = fopen(ias_cacert_path, "r")) == NULL) {
		k_set_error (error, STM_ERROR_INVALID_CERT_DATA, "Invalid IAS signing cert path: %s\n", ias_cacert_path);
	    	return ret;
	}

    	cert= PEM_read_X509(fp, NULL, NULL, NULL);
    	if ( cert == NULL ) {
		k_set_error (error, STM_ERROR_INVALID_CERT_DATA, "Reading X509 read IAS signing cert path: %s\n", ias_cacert_path);
    		fclose(fp);
		return ret;
	}
    	fclose(fp);

	stmsgx_epid_ssl_data::store = NULL;
	stmsgx_epid_ssl_data::store= X509_STORE_new();
	if ( stmsgx_epid_ssl_data::store == NULL ) {
	    k_set_error (error, STM_ERROR_INVALID_CERT_DATA, "CA Store creation failed\n");
	    return ret;
	}

	if ( X509_STORE_add_cert(stmsgx_epid_ssl_data::store, cert) != 1 ) {
	    k_set_error (error, STM_ERROR_INVALID_CERT_DATA, "Error in adding cert to CA CERT store\n");
	    X509_STORE_free(stmsgx_epid_ssl_data::store);
	    return ret;
	}
	ret = TRUE;
	return ret;
}



gboolean DLL_PUBLIC
stmsgx_get_epid_sigrl(sgx_quote_epid *epid,  GError **err)
{
	gboolean ret		    		= FALSE;
	g_return_val_if_fail( epid, ret );
	if( epid->data.sigrl.gid  == 0 )
	{                    
		k_info_msg(" error in fetching group id\n");
		return ret;  
	}

	GString *url				= NULL;
	GPtrArray *headers			= NULL;
	GPtrArray *res_headers			= NULL;
	gint res_https_code			= -1;
	char sgid[9];

	url 					= g_string_new(stmsgx_epid_ssl_data::ias_base_url);
	g_string_append(url, "/attestation/sgx/");
	g_string_append(url, stmsgx_epid_ssl_data::ias_version); 
	g_string_append(url, "/sigrl/");
        snprintf(sgid, 9, "%08x", epid->data.sigrl.gid);
	g_string_append(url, sgid);
	k_debug_msg("Sigrl req:%s\n", url->str);


 	headers               			= g_ptr_array_new ();
	g_ptr_array_add (headers, (gpointer) "Accept: application/json");
	g_ptr_array_add (headers, (gpointer) "Content-Type: application/json");

	set_quote_verify_ssl_options(&epid->ssl_opts);

	res_headers           			= g_ptr_array_new ();
 	epid->data.sigrl.sigrl 			= k_buffer_alloc(NULL,0);


	res_https_code 				= skc_https_send(url, headers, NULL,  res_headers, 
									epid->data.sigrl.sigrl, 
                                                                        &epid->ssl_opts, NULL, epid->debug);
	k_debug_msg("EPID Quote SIGRL response code:%d, sigrl:%s, sigrl length:%d\n", res_https_code, 
                          k_buffer_data(epid->data.sigrl.sigrl ), 
			  k_buffer_length(epid->data.sigrl.sigrl ));
	if( res_https_code == -1 || res_https_code == 0)
	{
	     k_set_error (err, STM_ERROR_IAS_SERVER_CONNCECTION, "IAS siGRL ended with status:%d\n", res_https_code);
	     goto out;
	}
	epid->https_response_code 	= res_https_code;
	if( res_https_code != 200)
	{
		k_info_msg("Error resonse got IAS for SigRL request:%d", res_https_code);
		goto out;
	}
	ret = TRUE;

out:
	g_string_free(url, TRUE);
        g_ptr_array_free(headers, TRUE);
        g_ptr_array_free(res_headers, TRUE);
	return ret;
}

gboolean DLL_LOCAL
set_quote_verify_ssl_options(keyagent_ssl_opts *ssl_opts)
{
	if( stmsgx_epid_ssl_data::cacert )
 		ssl_opts->ca_certfile		= strdup(stmsgx_epid_ssl_data::cacert);
	ssl_opts->ssl_verify		       	= stmsgx_epid_ssl_data::verify;
	ssl_opts->ssl_version		       	= CURL_SSLVERSION_TLSv1_2;
}

string DLL_LOCAL 
decode_cert(string str)
{
 	string decoded;
        size_t i;
        size_t len= str.length();

        for (i= 0; i< len; ++i) {
                if ( str[i] == '+' ) decoded+= ' ';
                else if ( str[i] == '%' ) {
                        char *e= NULL;
                        unsigned long int v;
                        if ( i+3 > len ) throw std::length_error("premature end of string");

                        v= strtoul(str.substr(i+1, 2).c_str(), &e, 16);

                        if ( *e ) throw std::out_of_range("invalid encoding");

                        decoded+= static_cast<char>(v);
                        i+= 2;
                } else decoded+= str[i];
        }
        return decoded;
}



void DLL_LOCAL
parse_verify_data_header(gpointer data, gpointer user_data)
{
    	gchar *str                          	= (gchar *)data;
    	epid_report_data *report_data           = (epid_report_data *)user_data;
    	gchar **parse_content                   = NULL;
	gchar *str_down				= g_ascii_strdown(str, -1);

    	if ( g_str_has_prefix (str_down,"x-iasreport-signing-certificate:") == TRUE )
    	{
        	parse_content                   = g_strsplit(str,":",-1);
		try{
			report_data->ias_signing_cert 
						= g_string_new(decode_cert(string(parse_content[1])).c_str());
		}catch(...){
			k_critical_msg("Decode cert failed");
		}
    	}else if ( g_str_has_prefix (str_down,"x-iasreport-signature:") == TRUE ){
        	parse_content                   = g_strsplit(str,":",-1);
		report_data->ias_report_sign	= g_string_new(parse_content[1]);
 	}else{
		k_debug_msg("other header:%s", str);
	}
	if(str_down)
		g_free(str_down);
	if(parse_content)
		g_strfreev(parse_content);
}

gboolean DLL_LOCAL
convert_pem_to_x509 (X509 **cert, const char *pemdata, size_t sz)
{
        BIO *bmem				= NULL;
	gboolean ret				= FALSE;
        bmem					= BIO_new(BIO_s_mem());
        if ( bmem == NULL ) {
		k_critical_msg("Read bio creation error\n");
                goto cleanup;
        }

        if ( BIO_write(bmem, pemdata, (int) sz) != (int) sz ) {
                goto cleanup;
        }

        *cert= PEM_read_bio_X509(bmem, NULL, NULL, NULL);
        if ( *cert == NULL ) 
	{
		k_critical_msg("Read bio pem error\n");
		goto cleanup;
	}
	ret					= TRUE;

cleanup:
        if ( bmem != NULL ) 
		BIO_free(bmem);
        return ret;
}

gboolean DLL_LOCAL 
verify_cert_chain( X509 **chain, gint cert_count, GError **err)
{
	X509_STORE_CTX *ctx			= NULL;
    	STACK_OF(X509) *stack			= NULL;
	gboolean ret				= FALSE;
	X509 *cert				= NULL;
	gint i					= 0;

    	stack					= sk_X509_new_null();
    	if ( stack == NULL ) {
	     	k_set_error (err,  STM_ERROR_IAS_SERVER_CERT_VERIFY, "IAS certs verfify: stack creation failed");
		goto out;
    	}

    	for ( i=0; i<=cert_count; i++) 
		sk_X509_push(stack, chain[i]);

        cert					= (X509 *)sk_X509_value(stack, 0);
        ctx					= X509_STORE_CTX_new();

        if ( ctx == NULL || stmsgx_epid_ssl_data::store == NULL ) {
	     	k_set_error (err,  STM_ERROR_IAS_SERVER_CERT_VERIFY, "IAS certs verfify: Store creation failed");
		goto out;
        }

        if ( X509_STORE_CTX_init(ctx, stmsgx_epid_ssl_data::store, cert, stack) != 1 ) {
	     	k_set_error (err,  STM_ERROR_IAS_SERVER_CERT_VERIFY, "IAS certs verfify: Store ctx init failed");
		goto out;
        }
	
        if ( X509_verify_cert(ctx) != 1 ){
		k_critical_msg("IAS Cert verfiy failed\n");
	     	k_set_error (err,  STM_ERROR_IAS_SERVER_CERT_VERIFY, "IAS certs verfify failed");
		goto out;
	} 
	ret					= TRUE;
out:
	if(stack)
		sk_X509_free(stack);
	if (ctx)
		X509_STORE_CTX_free(ctx);
	return ret;
}


gboolean DLL_LOCAL 
validate_ias_signing_cert(sgx_quote_epid *epid, GError **err)
{
	gboolean ret				= FALSE;
	g_return_val_if_fail(epid->data.report.ias_signing_cert, ret);
	GMatchInfo *matchInfo			= NULL;
	GRegex *regex				= NULL;
	gchar *cert				= NULL;
	gint count				= 0;
	X509 *tmp_cert				= NULL;
	gint i					= 0;
	vector<X509 *> certvec;
	EVP_PKEY *pkey				= NULL;


	regex 					= g_regex_new ("-----BEGIN .+?-----(?s).+?-----END .+?-----", 
								G_REGEX_RAW, 
								G_REGEX_MATCH_NEWLINE_LF, 
								err);
	if( *err )
	{
	     	k_set_error (err,  STM_ERROR_IAS_SERVER_CERT_VERIFY, "IAS certs chain parse error");
		goto out;
	}
        g_regex_match (regex, epid->data.report.ias_signing_cert->str, G_REGEX_MATCH_NEWLINE_LF, &matchInfo);
	if( g_match_info_matches(matchInfo) == ret)
	{
	     k_set_error (err,  STM_ERROR_IAS_SERVER_CERT_VERIFY, "IAS certs chain parse error");
	     goto out;
	} 
 
        while (g_match_info_matches(matchInfo)) {
             cert				= g_match_info_fetch (matchInfo, 0);
             ret 				= convert_pem_to_x509( &tmp_cert, cert, strlen(cert));
	     if( ret != TRUE || tmp_cert == NULL)
	     {
	     	k_set_error (err,  STM_ERROR_IAS_SERVER_CERT_VERIFY, "IAS certs chain parse: Error converting pem to x509 obj");
		goto out;
	     }

	     certvec.push_back(tmp_cert);

             g_match_info_next (matchInfo, err);
	     if( *err )
	     {
	     	g_free(cert);
	     	cert 				= NULL;
	    	k_set_error (err,  STM_ERROR_IAS_SERVER_CERT_VERIFY, "IAS certs chain parse error");
		goto out;
	     }
	     g_free(cert);
	     cert 				= NULL;
	     tmp_cert				= NULL;
	
        }
	count					= certvec.size();
        epid->data.report.cert_chain = (X509**) malloc(sizeof(X509 *)*(count+1));
        if (  epid->data.report.cert_chain == NULL ) {
	    	k_set_error (err,  STM_ERROR_IAS_SERVER_CERT_VERIFY, "IAS certs chain parse error");
                goto out;
        }
        for (i= 0; i< count; ++i) 
	{
		epid->data.report.cert_chain[i]	= certvec[i];
	}
        epid->data.report.cert_chain[count]	= NULL;
	ret					= verify_cert_chain( epid->data.report.cert_chain, 
									g_match_info_get_match_count(matchInfo), err);
out:
	if( cert )
		g_free(cert);
 	g_match_info_free (matchInfo);
  	g_regex_unref (regex);
	return ret;
}

gboolean  DLL_LOCAL 
sha256_verify(const unsigned char *msg, size_t mlen, unsigned char *sig,
    size_t sigsz, EVP_PKEY *pkey)
{
        EVP_MD_CTX *ctx				= NULL;
        gboolean ret 				= FALSE;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ctx					= EVP_MD_CTX_create();
#else
        ctx					= EVP_MD_CTX_new();
#endif
        if ( ctx == NULL ) {
		k_critical_msg("IAS Report SHA Verify: EVP_MD_CTX_new failed\n");
                goto cleanup;
        }

        if ( EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1 ) {
		k_critical_msg("IAS Report SHA Verify: EVP_DigestVerifyInit failed\n");
                goto cleanup;
        }

        if ( EVP_DigestVerifyUpdate(ctx, msg, mlen) != 1 ) {
		k_critical_msg("IAS Report SHA Verify: EVP_DigestVerifyUpdate failed\n");
                goto cleanup;
        }

        if ( EVP_DigestVerifyFinal(ctx, sig, sigsz) != 1 ){
		k_critical_msg("IAS Report SHA Verify: EVP_DigestVerifyFinal failed\n");
                goto cleanup;
	}
	ret 					= TRUE;
	k_debug_msg("Sha256 verify completed\n");

cleanup:
        if ( ctx != NULL ) 
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		EVP_MD_CTX_destroy(ctx);
#else
		EVP_MD_CTX_free(ctx);
#endif
        return ret;
}

gboolean  DLL_LOCAL 
validate_ias_sign(sgx_quote_epid *epid, GError **err)
{
	gboolean ret				= FALSE;
	g_return_val_if_fail(epid->data.report.ias_report_sign->str && epid->data.report.cert_chain, ret);
 	unsigned char *sig			= NULL;
	EVP_PKEY *pkey				= NULL;
	X509 *sign_cert				= NULL;
	size_t sigsz;
	int rv;

 	sig					= (unsigned char *) g_base64_decode(epid->data.report.ias_report_sign->str, &sigsz);
     	if ( sig == NULL ) {
	    	k_set_error (err,  STM_ERROR_IAS_SERVER_SIGN_VERIFY, "IAS Signature base64 decode fails");
                goto out;
        }
	sign_cert				= epid->data.report.cert_chain[0];
	pkey					= X509_get_pubkey(sign_cert);
	if ( pkey == NULL ) {
	    	k_set_error (err,  STM_ERROR_IAS_SERVER_SIGN_VERIFY, "Invalid Public Key");
                goto out;
        }

     	if ( epid->data.report.res_data == NULL ) {
	    	k_set_error (err,  STM_ERROR_IAS_SERVER_SIGN_VERIFY, "IAS Signature response buffer is null");
                goto out;
	}

	ret					= sha256_verify((const unsigned char *) k_buffer_data(epid->data.report.res_data),
              						k_buffer_length(epid->data.report.res_data), sig, sigsz, pkey);
	if( ret != TRUE ){
	    	k_set_error (err,  STM_ERROR_IAS_SERVER_SIGN_VERIFY, "IAS Signature verify: sha256_verify failed");
                goto out;
        }

out:
	if(sig)
		g_free(sig);
	return ret;
}

gboolean DLL_LOCAL 
validate_sgx_verify_response_header(sgx_quote_epid *epid, GPtrArray *res_headers,  GError **err)
{
	gboolean ret				= FALSE;
	g_return_val_if_fail( ( res_headers && epid ), ret);
	g_ptr_array_foreach (res_headers, parse_verify_data_header, (gpointer) &epid->data.report);
	if( validate_ias_signing_cert(epid, err) != TRUE )
	{
		return ret;
	}
	k_debug_msg("IAS Signature Certificate chain verifcation passed\n");
	if( validate_ias_sign(epid, err) != TRUE )
	{
		return ret;
	}
	ret 					= TRUE;
	k_debug_msg("IAS Signature verification passed\n");
	return ret;
}

void DLL_PUBLIC 
stmsgx_clear_epid_report_data(sgx_quote_epid *epid){

	if( epid != NULL ){

		if(epid->data.report.quote)
		      k_buffer_unref( epid->data.report.quote );
		k_string_free(epid->data.report.isv_enclave_quote_status, TRUE);
		k_string_free(epid->data.report.id, TRUE);
		k_string_free(epid->data.report.version, TRUE);
		k_string_free(epid->data.report.timestamp, TRUE);
		k_string_free(epid->data.report.isv_enclave_quote_body, TRUE);
		k_string_free(epid->data.report.ias_signing_cert, TRUE);
		k_string_free(epid->data.report.ias_report_sign, TRUE);
		if(epid->data.report.res_data)
		      k_buffer_unref( epid->data.report.res_data );
		if(epid->data.report.cert_chain)
		{
		      g_free(epid->data.report.cert_chain);
		      epid->data.report.cert_chain=NULL;
		}
	}
}

void DLL_PUBLIC 
stmsgx_clear_epid_sigrl_data(sgx_quote_epid *epid){
	if( epid != NULL ){
		if(epid->data.sigrl.sigrl)
		      k_buffer_unref( epid->data.sigrl.sigrl );
	}
}


gboolean DLL_PUBLIC 
stmsgx_epid_quote_verify(sgx_quote_epid *epid,  GError **err)
{
	gboolean ret		    		= FALSE;
	g_return_val_if_fail( ( epid && epid->data.report.quote ), ret );

	GString *url		      		= NULL;
	GString *sub_key		      	= NULL;
	GString *post_data	      		= NULL;
	GPtrArray *headers	      		= NULL;
	GPtrArray *res_headers	      		= NULL;
	gint res_https_code	      		= -1;

	Json::Value report_request;
	Json::Value report_response;
	Json::StreamWriterBuilder builder;


	url = g_string_new(stmsgx_epid_ssl_data::ias_base_url);
	g_string_append(url, "/attestation/");
	g_string_append(url, stmsgx_epid_ssl_data::ias_version); 
	g_string_append(url, "/report");


	sub_key = g_string_new("Ocp-Apim-Subscription-Key: ");
	g_string_append(sub_key, stmsgx_epid_ssl_data::ias_sub_key);

	k_debug_msg("Quote:%s\nQuote Len:%d\n", k_buffer_data(epid->data.report.quote), k_buffer_length(epid->data.report.quote));
	k_debug_msg("Subscription key:%s\n", sub_key->str);

	report_request["isvEnclaveQuote"] 	= (gchar *) k_buffer_data(epid->data.report.quote);

 	headers               			= g_ptr_array_new ();
	g_ptr_array_add (headers, (gpointer) "Accept: application/json");
	g_ptr_array_add (headers, (gpointer) "Content-Type: application/json");
	g_ptr_array_add (headers, (gpointer) sub_key->str);

	res_headers           			= g_ptr_array_new ();
	epid->data.report.res_data		= k_buffer_alloc(NULL, 0);
	builder.settings_["indentation"]    	= "";
	post_data                               = g_string_new(Json::writeString(builder, report_request).c_str());
	json_print(report_request);
	
	set_quote_verify_ssl_options(&epid->ssl_opts);
	res_https_code 				= skc_https_send(url, headers, post_data,  res_headers, epid->data.report.res_data, 
                                                                        &epid->ssl_opts, NULL, epid->debug);
	k_debug_msg("EPID Quote Report response code:%d", res_https_code);
	if( res_https_code == -1 ){
	     	k_set_error (err, STM_ERROR_IAS_SERVER_CONNCECTION, "IAS Report https  ended with error");
	     	goto out;
	}
	epid->https_response_code 		= res_https_code;
	if( res_https_code != 200)
	{
		k_info_msg("Error resonse got from IAS for Qutote Verfity request:%d", res_https_code);
	     	k_set_error (err, STM_ERROR_IAS_SERVER_CONNCECTION, "Error resonse got from IAS for Qutote Verfity request:%d", 
						res_https_code);
		goto out;
	}

	ret					= validate_sgx_verify_response_header( epid, res_headers, err);
	if( ret != TRUE)
	{
		k_info_msg("Header validation not successful\n");
		goto out;
	}
	report_response				= parse_data(epid->data.report.res_data, epid->debug);
 	try{
                epid->data.report.isv_enclave_quote_status  
                                                = g_string_new(get_json_value(report_response,
							  (const char *)"isvEnclaveQuoteStatus").c_str());
                epid->data.report.version 
                                                = g_string_new(get_json_value(report_response,
							  (const char *)"version").c_str());
                epid->data.report.id 
                                                = g_string_new(get_json_value(report_response,
							  (const char *)"id").c_str());
                epid->data.report.isv_enclave_quote_body 
                                                = g_string_new(get_json_value(report_response,
							  (const char *)"isvEnclaveQuoteBody").c_str());

                epid->data.report.timestamp 
                                                = g_string_new(get_json_value(report_response,
							  (const char *)"timestamp").c_str());

        }catch(exception& e){
                 k_set_error (err, STM_ERROR_JSON_PARSE, "STM EPID JSON Parse error: %s\n", e.what());
                 goto out;
        }
	k_debug_msg("\nID:%s\nversion:%s\nEnclave Quote Status: %s\nEnclave Quote Body:%s\nTimestamp:%s\n",
			epid->data.report.id->str,
			epid->data.report.version->str,
			epid->data.report.isv_enclave_quote_status->str,
			epid->data.report.isv_enclave_quote_body->str,
			epid->data.report.timestamp->str
	);
	ret 					= TRUE;
out:
	g_string_free(post_data, TRUE);
	g_string_free(url, TRUE);
	g_string_free(sub_key, TRUE);
        g_ptr_array_free(headers, TRUE);
        g_ptr_array_free(res_headers, TRUE);
	return ret;
}

gboolean DLL_PUBLIC 
stmsgx_get_extended_epid_group_id(uint32_t *e_gid)
{
	sgx_status_t status;
	sgx_target_info_t   targetInfo =    { 0 };
        sgx_epid_group_id_t gid =           { 0 };

        status = sgx_init_quote(&targetInfo, &gid);
	if ( status != SGX_SUCCESS )
	{
		k_debug_msg("Error: fetch Extended epid group id failed, status:%0x\n",  status);
		return FALSE;
	}
	memcpy(e_gid, &gid, sizeof(sgx_epid_group_id_t));
	return TRUE;
}

