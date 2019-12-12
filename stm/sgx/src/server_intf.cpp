#define G_LOG_DOMAIN "stm-sgx"
#include "key-agent/key_agent.h"
#include "config-file/key_configfile.h"
#include "key-agent/stm/stm.h"
#include "k_errors.h"
#include "sgx_ecdsa_quote_verify.h"
#include <glib.h>
#include <glib/gi18n.h>
#include <errno.h>
#include <iostream>
#include <memory>
#include "internal.h"
#include "include/k_debug.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>

#include <sgx_quote.h>
#include "sgx_epid_quote_verify.h"
#include "config-file/key_configfile.h"
#include "config.h"

#define SHA256_SIZE 32
namespace sgx_server_sgx_stm{
	void 	*config;
	GString *configfile;
	const char *attestation_type;
	gboolean debug;
	gint quote_type;
	GString *tcbInfoURL;
    const char* qeIdentityPath;
    const char* qeIdentityFileType;
}

using namespace std;
using namespace stmsgx_epid_ssl_data;
using BIO_MEM_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

extern "C" gboolean
sgxstm_read_epid_quote_config(void *config, GError **err)
{
	gboolean ret				= FALSE;
	stmsgx_epid_ssl_data::ias_base_url      = key_config_get_string(config, "EPID_DATA_SERVER", "ias_base_url", err);
	if( *err )
		return ret;
        stmsgx_epid_ssl_data::ias_version       = key_config_get_string(config, "EPID_DATA_SERVER", "ias_api_version", err);
	if( *err )
		return ret;

	stmsgx_epid_ssl_data::ias_cacert  	= key_config_get_string(config, "EPID_DATA_SERVER", "ias_signing_cert", err);
	if( *err )
		return ret;

    stmsgx_epid_ssl_data::ias_sub_key       = key_config_get_string(config, "EPID_DATA_SERVER", "ias_subcription_key", err);
	if( *err )
		return ret;

        stmsgx_epid_ssl_data::verify            = key_config_get_boolean_optional(config, "EPID_DATA_SERVER", "ssl_verify", true);

 	if( 	(access( stmsgx_epid_ssl_data::ias_cacert, F_OK ) == -1) ){
        	g_set_error (err, STM_ERROR, STM_ERROR_INVALID_CERT_DATA,
                     "Invalid IAS Signing Cert Path:%s", stmsgx_epid_ssl_data::ias_cacert);
                return ret;
        }

	return TRUE;
}

extern "C" void
server_stm_init(const char *config_directory, GError **err)
{
	gboolean ret				= FALSE;
	g_return_if_fail( ((err || (err?*err:NULL)) && config_directory));

	sgx_server_sgx_stm::configfile 	= g_string_new(g_build_filename(config_directory, "sgx_stm.ini", NULL));
	sgx_server_sgx_stm::config 		= key_config_openfile(sgx_server_sgx_stm::configfile->str, err);
	if (*err)
	    return;
	sgx_server_sgx_stm::debug 		= key_config_get_boolean_optional(sgx_server_sgx_stm::config, "core", "debug", false);
	sgx_server_sgx_stm::attestation_type = key_config_get_string(sgx_server_sgx_stm::config, "core", "type", err);
	if (strcmp(sgx_server_sgx_stm::attestation_type, "ECDSA") == 0) {
		sgx_server_sgx_stm::tcbInfoURL = g_string_new(key_config_get_string(sgx_server_sgx_stm::config, "ECDSA", "tcbinfo_url", err));
		sgx_server_sgx_stm::qeIdentityPath = key_config_get_string_optional(sgx_server_sgx_stm::config, "ECDSA", "qe_identity_file", NULL);
		sgx_server_sgx_stm::qeIdentityFileType = key_config_get_string_optional(sgx_server_sgx_stm::config, "ECDSA", "qe_identity_file_type", NULL);
		if (*err) {
			return;
		}
	}
        OpenSSL_add_all_algorithms();
}

extern "C" void
server_stm_finalize(){
}

extern "C" gboolean
server_stm_activate(GError **err)
{
    return TRUE;
}

typedef struct {
  guint8 bytes[16];
} stm_uuid;

static gchar *
uuid_to_string (const stm_uuid *uuid)
{
  const guint8 *bytes;
  bytes = uuid->bytes;
  return g_strdup_printf ("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x"
                          "-%02x%02x%02x%02x%02x%02x",
                          bytes[0], bytes[1], bytes[2], bytes[3],
                          bytes[4], bytes[5], bytes[6], bytes[7],
                          bytes[8], bytes[9], bytes[10], bytes[11],
                          bytes[12], bytes[13], bytes[14], bytes[15]);
}

static void
uuid_set_version (stm_uuid *uuid, guint version)
{
  guint8 *bytes = uuid->bytes;
  /*
   * Set the four most significant bits (bits 12 through 15) of the
   * time_hi_and_version field to the 4-bit version number from
   * Section 4.1.3.
   */
  bytes[6] &= 0x0f;
  bytes[6] |= version << 4;
  /*
   * Set the two most significant bits (bits 6 and 7) of the
   * clock_seq_hi_and_reserved to zero and one, respectively.
   */
  bytes[8] &= 0x3f;
  bytes[8] |= 0x80;
}

static void
uuid_generate_v4 (stm_uuid *uuid)
{
  int i;
  guint8 *bytes;
  guint32 *ints;
  bytes = uuid->bytes;
  ints = (guint32 *) bytes;
  for (i = 0; i < 4; i++)
    ints[i] = g_random_int ();

  uuid_set_version (uuid, 4);
}

__attribute__ ((visibility("default")))
gboolean
stm_challenge_generate_request(const gchar **request, GError **error)
{
    g_return_val_if_fail(request != NULL, FALSE);
    stm_uuid uuid;
    uuid_generate_v4 (&uuid);
    *request = uuid_to_string (&uuid);
    return TRUE;
}


#if OPENSSL_VERSION_NUMBER < 0x10100000L

extern "C" {

static int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}
};

#endif

#define rsa_modulus_len(I)  (I)->keydetails.rsa.modulus_len
#define rsa_exponent_len(I)  (I)->keydetails.rsa.exponent_len

/**
 * quote: This is use to extract public key.
 * certificatesSize: This represents the total size of cecrtificates passed from api module for verification.
 * In traversing the buffer this size is needed to get to the sgx quote as now buffer will have 
 * certificates + quote.
 */
static RSA *
extract_pubkey_from_quote(k_buffer_ptr quote, gint type)//, u_int32_t certificatesSize)
{
	int ret = FALSE;
	RSA *rsa = NULL;
	BIGNUM *bn_e = NULL;
	BIGNUM *bn_n = NULL;
	k_buffer_ptr publickey_hash_in_quote = NULL;
	k_buffer_ptr hash_data = NULL;
	gsize hash_data_size = SHA256_SIZE;
	GChecksum *hash = NULL;

	u_int32_t pckCert_size = 0;
	struct keyagent_sgx_quote_info *quote_info = (struct keyagent_sgx_quote_info *)k_buffer_data(quote);
	if(type == KEYAGENT_SGX_QUOTE_TYPE_ECDSA )
		pckCert_size = (quote_info)->quote_details.ecdsa_quote_details.pckCert_size;
	u_int32_t public_key_size = rsa_modulus_len(quote_info) + rsa_exponent_len(quote_info);

	do {
        sgx_quote_t* sgxQuote  = (sgx_quote_t*)(k_buffer_data(quote) + sizeof(struct keyagent_sgx_quote_info) + pckCert_size + public_key_size);
        publickey_hash_in_quote = k_buffer_alloc(sgxQuote->report_body.report_data.d, SHA256_SIZE);

        // Compute hash of publicKeyData..
		if ((hash_data = k_buffer_alloc(NULL, SHA256_SIZE)) == NULL)
			break;

		if ((hash = g_checksum_new(G_CHECKSUM_SHA256)) == NULL)
			break;

		g_checksum_update(hash, k_buffer_data(quote) + sizeof(struct keyagent_sgx_quote_info) + pckCert_size, public_key_size);
		g_checksum_get_digest(hash, k_buffer_data(hash_data), &hash_data_size);
        if (!k_buffer_equal(publickey_hash_in_quote, hash_data)) {
            k_debug_msg("FAILED : Public key hash and hash in quote mismatch!");
            break;
        }

		if ((rsa = RSA_new()) == NULL)
			break;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
		RSA_set_method(rsa, 
			RSA_PKCS1_SSLeay());
#else
		RSA_set_method(rsa, 
			RSA_PKCS1_OpenSSL());
#endif

		bn_e = BN_new();
		bn_n = BN_new();

		if (!bn_e || !bn_n)
			break;

		if (!BN_bin2bn(k_buffer_data(quote) + sizeof(struct keyagent_sgx_quote_info) + pckCert_size, rsa_exponent_len(quote_info), bn_e)) {
			k_debug_msg("can;t create bn-e");
			break;
		}

		if (!BN_bin2bn(k_buffer_data(quote) + sizeof(struct keyagent_sgx_quote_info) + pckCert_size+ rsa_exponent_len(quote_info), rsa_modulus_len(quote_info), bn_n)) {
			k_debug_msg("can;t create bn-n");
			break;
		}
		if (!RSA_set0_key(rsa, bn_n, bn_e, NULL)) {
			k_debug_msg("RSA_set0_key failed");
			break;
		}
		ret = TRUE;
	} while (FALSE);

	if (!ret) {
		if (rsa) RSA_free(rsa);
		rsa = NULL;
		BN_free(bn_e);
		BN_free(bn_n);
	}

	if (hash) g_checksum_free(hash);
	k_buffer_unref(publickey_hash_in_quote);
	k_buffer_unref(hash_data);
	return rsa;
}

__attribute__ ((visibility("default")))
gboolean
stm_challenge_verify(k_buffer_ptr quote, k_attribute_set_ptr *challenge_attrs, GError **error)
{
    gboolean ret 				= FALSE;
    k_buffer_ptr CHALLENGE_RSA_PUBLIC_KEY 	= NULL;
    BIO* bio 					= NULL;
    RSA *rsa 					= NULL;
    int len 					= 0;
    unsigned char *tmp 				= NULL;
    k_attribute_set_ptr challenge_set 		= NULL;
    BUF_MEM *mem 				= NULL;
    struct keyagent_sgx_quote_info *quote_info  = NULL;
    u_int32_t public_key_size 			= 0;
    sgx_quote_t *sgxQuote			= NULL;

    k_buffer_ptr SGX_ENCLAVE_ISSUER 		= NULL;
    k_buffer_ptr SGX_ENCLAVE_PROD_ID 		= NULL;
    k_buffer_ptr SGX_ENCLAVE_EXT_PROD_ID 	= NULL;
    k_buffer_ptr SGX_ENCLAVE_MEASUREMENT 	= NULL;
    k_buffer_ptr SGX_CONFIG_ID_SVN 		= NULL;
    k_buffer_ptr SGX_ENCLAVE_SVN_MINIMUM 	= NULL;
    k_buffer_ptr SGX_CONFIG_ID 			= NULL;
    k_buffer_ptr CHALLENGE_KEYTYPE		= NULL;

    g_autoptr (GError) err 			= NULL;
    gchar *encoded_sgx_quote 			= NULL;
    sgx_quote_epid epid;

    unsigned char prod_id[2];
    unsigned char config_svn[2];
    unsigned char enclave_svn_min[2];

    BIO_MEM_ptr mbio(BIO_new(BIO_s_mem()), ::BIO_free);

    quote_info 					= (struct keyagent_sgx_quote_info *)k_buffer_data(quote);
    sgx_server_sgx_stm::quote_type		= quote_info->quote_type;
    server_stm_init(SKC_CONF_PATH, &err);
    if( err )
    {
	    k_debug_error(err);
	    return ret;
    }


    if (sgx_server_sgx_stm::quote_type == KEYAGENT_SGX_QUOTE_TYPE_EPID){

		public_key_size 				= rsa_modulus_len(quote_info) + rsa_exponent_len(quote_info);
		sgxQuote  					= (sgx_quote_t*)(k_buffer_data(quote) + 
						sizeof(struct keyagent_sgx_quote_info) + public_key_size);
		encoded_sgx_quote 				= g_base64_encode((const guchar *)sgxQuote, quote_info->quote_size);

		ret					= sgxstm_read_epid_quote_config(sgx_server_sgx_stm::config, &err);
		if( err != NULL )
		{
				k_debug_error(err);
				return ret;
		}
		stmsgx_put_ias_signing_cert_to_store(stmsgx_epid_ssl_data::ias_cacert, &err);
		if( err != NULL )
		{
				k_debug_error(err);
				return ret;
		}
		memset( &epid, 0x00, sizeof(sgx_quote_epid));
		epid.debug				= sgx_server_sgx_stm::debug;
		epid.data.report.quote   		= k_buffer_alloc( strdup(encoded_sgx_quote), strlen(encoded_sgx_quote));
		ret 					= stmsgx_epid_quote_verify(&epid,  &err);
		if( ret != TRUE  && err)
		{
				g_free(encoded_sgx_quote);
				stmsgx_clear_epid_report_data(&epid);
				k_debug_error(err);
				return ret;
		}

		if(  g_strcmp0(epid.data.report.isv_enclave_quote_status->str, "OK") != 0)
		{
				k_info_msg("Enclave Quote Status not equal to OK instead received :%s\n",
								epid.data.report.isv_enclave_quote_status->str);
		}
		stmsgx_clear_epid_report_data(&epid);
		g_free(encoded_sgx_quote);
#ifdef QUOTE_DUMP
		const gchar *quote_file			= "/tmp/quote_server.txt";
		ret 					= g_file_set_contents (quote_file,
						encoded_sgx_quote,
						strlen(encoded_sgx_quote),
						error);

		if(ret != TRUE)
		{
				k_info_msg("quote write to file failed\n");
		}
#endif
		rsa = extract_pubkey_from_quote(quote, KEYAGENT_SGX_QUOTE_TYPE_EPID);
	} else if(sgx_server_sgx_stm::quote_type == KEYAGENT_SGX_QUOTE_TYPE_ECDSA){
			public_key_size = rsa_modulus_len(quote_info) + rsa_exponent_len(quote_info);
			u_int32_t pckCert_size = (quote_info)->quote_details.ecdsa_quote_details.pckCert_size;
			u_int32_t quoteSize = (quote_info)->quote_size;

			k_debug_msg("attestation_type: %d", sgx_server_sgx_stm::quote_type);
			k_debug_msg("pckCert_size: %d", pckCert_size);
			k_debug_msg("keyagent_sgx_quote_info size: %d", sizeof(struct keyagent_sgx_quote_info));
			k_debug_msg("public_key_size: %d", public_key_size);
			k_debug_msg("quoteSize: %d", quoteSize);

			sgxQuote  = (sgx_quote_t*)(k_buffer_data(quote) + sizeof(struct keyagent_sgx_quote_info) + public_key_size + pckCert_size);
			rsa = extract_pubkey_from_quote(quote, KEYAGENT_SGX_QUOTE_TYPE_ECDSA);
	} else {
			k_critical_msg("invalid attestaion type");
			return ret;
	}
	if( ret == FALSE && err )
	{
			k_debug_error(err);
			return ret;
	}
	*challenge_attrs 				= NULL;
	if (!rsa) {
			goto out;
	} else {
			if (sgx_server_sgx_stm::quote_type == KEYAGENT_SGX_QUOTE_TYPE_ECDSA) {
				if (!verifyEcdsaQuote(quote, public_key_size, 0, sgx_server_sgx_stm::tcbInfoURL, sgx_server_sgx_stm::qeIdentityPath)) {
						goto out;
				}
			}

			len = i2d_RSA_PUBKEY(rsa, NULL);
			i2d_RSA_PUBKEY_bio(mbio.get(), rsa);
			BIO_get_mem_ptr(mbio.get(), &mem);
			CHALLENGE_RSA_PUBLIC_KEY = k_buffer_alloc(mem->data, mem->length);

			*challenge_attrs = challenge_set = k_attribute_set_alloc(9);

			CHALLENGE_KEYTYPE = k_buffer_alloc(NULL, strlen("RSA")+1);
			strcpy((char *)k_buffer_data(CHALLENGE_KEYTYPE), "RSA");
			k_attribute_set_add_attribute(challenge_set, (char *)"CHALLENGE_KEYTYPE", CHALLENGE_KEYTYPE);
			k_attribute_set_add_attribute(challenge_set, (char *)"CHALLENGE_RSA_PUBLIC_KEY", CHALLENGE_RSA_PUBLIC_KEY);

			SGX_ENCLAVE_ISSUER = k_buffer_alloc(NULL, sizeof(sgx_measurement_t));
			memcpy(k_buffer_data(SGX_ENCLAVE_ISSUER), (unsigned char *)(sgxQuote->report_body.mr_signer.m), sizeof(sgx_measurement_t));

			prod_id[0] = sgxQuote->report_body.isv_prod_id >> 8;
			prod_id[1] = sgxQuote->report_body.isv_prod_id & 0x00FF;
			SGX_ENCLAVE_PROD_ID = k_buffer_alloc(prod_id, sizeof(sgxQuote->report_body.isv_prod_id));

			SGX_ENCLAVE_EXT_PROD_ID	= k_buffer_alloc(NULL, sizeof(sgxQuote->report_body.isv_ext_prod_id));
			memcpy(k_buffer_data(SGX_ENCLAVE_EXT_PROD_ID), (unsigned char *)(sgxQuote->report_body.isv_ext_prod_id), sizeof(sgx_isvext_prod_id_t));

			SGX_ENCLAVE_MEASUREMENT = k_buffer_alloc(NULL, sizeof(sgx_measurement_t));
			memcpy(k_buffer_data(SGX_ENCLAVE_MEASUREMENT), (unsigned char *)(sgxQuote->report_body.mr_enclave.m), sizeof(sgx_measurement_t));

			config_svn[0] = sgxQuote->report_body.config_svn >> 8;
			config_svn[1] = sgxQuote->report_body.config_svn & 0x00FF;
			SGX_CONFIG_ID_SVN = k_buffer_alloc(config_svn, sizeof(sgxQuote->report_body.config_svn));

			enclave_svn_min[0] = sgxQuote->report_body.isv_svn >> 8;
			enclave_svn_min[1] = sgxQuote->report_body.isv_svn & 0x00FF;
			SGX_ENCLAVE_SVN_MINIMUM	= k_buffer_alloc(enclave_svn_min, sizeof(sgxQuote->report_body.isv_svn));

			SGX_CONFIG_ID = k_buffer_alloc(NULL, sizeof(sgx_config_id_t));
			memcpy(k_buffer_data(SGX_CONFIG_ID), (unsigned char *)(sgxQuote->report_body.config_id), sizeof(sgx_config_id_t));

			k_attribute_set_add_attribute(challenge_set, (char *)"SGX_ENCLAVE_ISSUER", SGX_ENCLAVE_ISSUER);
			k_attribute_set_add_attribute(challenge_set, (char *)"SGX_ENCLAVE_ISSUER_PRODUCT_ID", SGX_ENCLAVE_PROD_ID);
			k_attribute_set_add_attribute(challenge_set, (char *)"SGX_ENCLAVE_ISSUER_EXTENDED_PRODUCT_ID", SGX_ENCLAVE_EXT_PROD_ID);
			k_attribute_set_add_attribute(challenge_set, (char *)"SGX_ENCLAVE_MEASUREMENT", SGX_ENCLAVE_MEASUREMENT);
			k_attribute_set_add_attribute(challenge_set, (char *)"SGX_CONFIG_ID_SVN", SGX_CONFIG_ID_SVN);
			k_attribute_set_add_attribute(challenge_set, (char *)"SGX_ENCLAVE_SVN_MINIMUM", SGX_ENCLAVE_SVN_MINIMUM);
			k_attribute_set_add_attribute(challenge_set, (char *)"SGX_CONFIG_ID", SGX_CONFIG_ID);

			ret = TRUE;
	}
out:
	if (CHALLENGE_RSA_PUBLIC_KEY) k_buffer_unref(CHALLENGE_RSA_PUBLIC_KEY);
	if (CHALLENGE_KEYTYPE) k_buffer_unref(CHALLENGE_KEYTYPE);
	if (rsa) RSA_free(rsa);
	if (SGX_ENCLAVE_ISSUER) k_buffer_unref(SGX_ENCLAVE_ISSUER);
	if (SGX_ENCLAVE_PROD_ID) k_buffer_unref(SGX_ENCLAVE_PROD_ID);
	if (SGX_ENCLAVE_EXT_PROD_ID) k_buffer_unref(SGX_ENCLAVE_EXT_PROD_ID);
	if (SGX_ENCLAVE_MEASUREMENT) k_buffer_unref(SGX_ENCLAVE_MEASUREMENT);
	if (SGX_CONFIG_ID_SVN) k_buffer_unref(SGX_CONFIG_ID_SVN);
	if (SGX_ENCLAVE_SVN_MINIMUM) k_buffer_unref(SGX_ENCLAVE_SVN_MINIMUM);
	if (SGX_CONFIG_ID) k_buffer_unref(SGX_CONFIG_ID);

	k_info_msg("Exit from quote verify with status:%d", ret);
	return ret;
}
