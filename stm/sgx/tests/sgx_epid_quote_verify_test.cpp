#define G_LOG_DOMAIN "SGX-QUOTE-VERIFY-TEST"


#include <glib.h>
#include <unistd.h>
#include "k_types.h"
#include "k_errors.h"
#include "stm/sgx/src/sgx_epid_quote_verify.h"

using namespace stmsgx_epid_ssl_data;

gboolean do_sigrl_test(GError **err);
gboolean do_epid_quote_verify_test(GError **err);
gchar *quote_buffer_file=NULL;

gboolean do_sigrl_test(GError **err)
{
	gboolean ret = FALSE;
	sgx_quote_epid epid;
	memset(&epid, 0x00, sizeof(sgx_quote_epid));
	epid.debug				= TRUE;

	if( stmsgx_get_extended_epid_group_id(&epid.data.sigrl.gid) != TRUE )
	{
		k_critical_msg("Error in getting extended group id\n");
		return ret;
	}
	ret = stmsgx_get_epid_sigrl(&epid, err);
	if( ret != TRUE )
	{
		k_critical_error(*err);
	}
	stmsgx_clear_epid_sigrl_data(&epid);
	return TRUE;
}


gboolean do_epid_quote_verify_test(GError **err)
{
	gboolean ret 	= FALSE;
	gchar *quote	= NULL;
	sgx_quote_epid epid;
	gsize	length	= 0;


	memset(&epid, 0x00, sizeof(sgx_quote_epid));
	epid.debug	= TRUE;

	
	if( g_file_get_contents ((const gchar *)quote_buffer_file,
                    	&quote,
                     	&length,
                     	err) != TRUE )
	{
		k_critical_msg("Error in reading quote buffer file\n");
		return ret;
	}


	//gchar *quote="AgABAC4LAAAIAAcAAAAAADupL4bXsLXv6JysbPRW3aoAAAAAAAAAAAAAAAAAAAAABQYCBP8CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAHhFGuIay9RqyfZvGh3vqRvlxuXPQAfAZcP94DDdfKEOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9ccY4Dvd8VBfostHOLUtlBLn0GOUEk0JEDP/yRD2VvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABzl+jSfAWkKJp0A3zn4wHCoLNO86bfQRNIIR0eOgZ5nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAAJNUd1lzoGYqGAas5uT3Tj7pjwPe0/2RQ7mhdpjPkNKB325nUUR5TzcGtLISXADPoMGDvv43KgHA/+UXKWgbA5hE9bzE78TnaTorpe5whm6YMVcEYmAsub2iyoh+A3X957nYDVoQpM2O/6U/t8cPbw0LZcEtGd1uVfpW7qgyScaN8wLncAiWmsK/cJeDvtYKop6r3gqsXmUB5xp4ayvOeC5s7vuNXVcpoXyTpi2anGVQDA2LVMRD0GJajwSdXQr8h923kK5IISIBbf91kKUZ5EU3XUyQU4M06pSW+IflaCcaNEzdYMG4iDWCXt1aEluH5T/k46Ak1CxQxFvadG6ZGmXJKH9To6HOTclTUJ/O1hOX7eeFTOYJjcyYI9SYi8Fbv+Ev4foPiC7CeKZv42gBAAD6l4fsGzlI4T8pqKV7Ti7DA8Q2JL1stf0b3EHXb1Gp9i9PRuTri32Xq9kM8rhRwMWMykq+jqQ3YoE+j3sRfYJKRpQqmUyR63/lOmvJYx5UEFABiLTwcxnXNwGw5xVoDrSdc4n8/avM2oBNtaCUra1Jxk/ulLe7+QQxkNMkeFR2BMOVueAdkqfD4ujMpPQvVsgXbrBdp73rBvYv9QIEXyOg43YHXcY0jcl6mOjT+XP+vHxaNmlyRuNCzJKlmyteE0wr4avj2uJ8C1KKwOkVoFTm2qYREH68YMeOaVNFaMUVqrpdPBPlaNAeZlwfQrH7OB5yvnVeo/esU57uyfjz+sw9B3LZpFSUlIOxDcUipKPrL1UxglxIGhJlISoFwMe9/DZX2IcPkXb8ScN/JHc6kO850kXJ+PdMMhlurmdOTNZ+qUMM8fJIhBUfSXQfkqrzPhMLAmydwmVovxjDVgxrR+oeKJIAKxxEOQcEAXIOXtPyOsJlow9Eio6N";
	k_debug_msg("quote len:%d, size:%d, quote:%s", strlen(quote), length, quote);

	epid.data.report.quote  		= k_buffer_alloc( strdup(quote), strlen(quote));
	ret = stmsgx_epid_quote_verify(&epid,  err);
	if( ret != TRUE  && *err)
	{
		k_critical_error(*err);
	}
	stmsgx_clear_epid_report_data(&epid);
	g_free(quote);
	return ret;

}

int main ( int argc, char **argv )
{
	setenv("G_MESSAGES_DEBUG", "all", 1);
	gboolean ret = FALSE;
	g_autoptr(GError) err = NULL;

    if( argc < 3 )
	{
        k_critical_msg("Insufficient inputs: %s <AttestationReportSigningCACert.pem> <IAS_SUBSCRIPTION_KEY> <QUOTE_BUFFER_FILE_PATH>\n", argv[0]);
		return 0;
	}

    k_debug_msg("IAS Signing Cert:%s\nIAS Sub Key:%s\nBuffer Quote:%s\n",
        argv[1], argv[2], argv[3]);


    stmsgx_epid_ssl_data::ias_base_url      = "https://api.trustedservices.intel.com/sgx/dev";
	stmsgx_epid_ssl_data::ias_version  	= "v3";
	stmsgx_epid_ssl_data::ias_cacert  	= argv[1];
    stmsgx_epid_ssl_data::ias_sub_key   = argv[2];
    quote_buffer_file                   = argv[3];

 	//stmsgx_epid_ssl_data::cacert  		= "/etc/pki/tls/certs/ca-bundle.crt";
	stmsgx_epid_ssl_data::verify     	= TRUE;

	if(	(access( stmsgx_epid_ssl_data::ias_cacert, F_OK ) == -1) ||  
		(access( quote_buffer_file, F_OK ) == -1) )
	{
		k_critical_msg("Input files are invalid\n");
		return 0;
	}


	stmsgx_put_ias_signing_cert_to_store(stmsgx_epid_ssl_data::ias_cacert, &err);
	if( err != NULL )
	{
		k_critical_error(err);
		return ret;
	}
	//do_sigrl_test(&err);
	do_epid_quote_verify_test(&err);
	return 0;
}


