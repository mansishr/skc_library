#define G_LOG_DOMAIN "stm-sgx"
#include "key-agent/key_agent.h"
#include "key-agent/stm/stm.h"
#include "k_errors.h"
#include <glib.h>
#include <glib/gi18n.h>
#include <errno.h>
#include <iostream>
#include <memory>
#include "internal.h"
#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>

#include <sgx_quote.h>

#define SHA256_SIZE 32

using namespace std;
using BIO_MEM_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

extern "C" void
server_stm_init(const char *config_directory, GError **err)
{
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

static RSA *
local_verify_quote(k_buffer_ptr quote)
{
	int ret = FALSE;
	RSA *rsa = NULL;
	BIGNUM *bn_e = NULL;
	BIGNUM *bn_n = NULL;
	k_buffer_ptr publickey_hash_in_quote = NULL;
	k_buffer_ptr hash_data = NULL;
	gsize hash_data_size = SHA256_SIZE;
	GChecksum *hash = NULL;

	struct keyagent_sgx_quote_info *quote_info = (struct keyagent_sgx_quote_info *)k_buffer_data(quote);
    u_int32_t public_key_size = rsa_modulus_len(quote_info) + rsa_exponent_len(quote_info);

	do {
        sgx_quote_t* sgxQuote  = (sgx_quote_t*)(k_buffer_data(quote) + sizeof(struct keyagent_sgx_quote_info) + public_key_size);
        publickey_hash_in_quote = k_buffer_alloc(sgxQuote->report_body.report_data.d, SHA256_SIZE);

        // Compute hash of publicKeyData..
		if ((hash_data = k_buffer_alloc(NULL, SHA256_SIZE)) == NULL)
			break;

		if ((hash = g_checksum_new(G_CHECKSUM_SHA256)) == NULL)
			break;

		g_checksum_update(hash, k_buffer_data(quote) + sizeof(struct keyagent_sgx_quote_info), public_key_size);
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

		if (!BN_bin2bn(k_buffer_data(quote) + sizeof(struct keyagent_sgx_quote_info), rsa_exponent_len(quote_info), bn_e)) {
			k_debug_msg("can;t create bn-e");
			break;
		}

		if (!BN_bin2bn(k_buffer_data(quote) + sizeof(struct keyagent_sgx_quote_info) + rsa_exponent_len(quote_info), rsa_modulus_len(quote_info), bn_n)) {
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
    gboolean ret = FALSE;
    k_buffer_ptr CHALLENGE_RSA_PUBLIC_KEY = NULL;
    k_buffer_ptr SW_ISSUER = NULL;
    BIO* bio = NULL;
    RSA *rsa = NULL;
    int len = 0;
    unsigned char *tmp = NULL;
    k_attribute_set_ptr challenge_set = NULL;
    BIO_MEM_ptr mbio(BIO_new(BIO_s_mem()), ::BIO_free);
    BUF_MEM *mem = NULL;

    SW_ISSUER = k_buffer_alloc(NULL, strlen("Intel")+1);
    strcpy((char *)k_buffer_data(SW_ISSUER), "Intel");

    *challenge_attrs = NULL;

	rsa = local_verify_quote(quote);
	if (!rsa)
		goto out;

    len = i2d_RSA_PUBKEY(rsa, NULL);
    i2d_RSA_PUBKEY_bio(mbio.get(), rsa);
    BIO_get_mem_ptr(mbio.get(), &mem);
    CHALLENGE_RSA_PUBLIC_KEY = k_buffer_alloc(mem->data, mem->length);

    *challenge_attrs = challenge_set = k_attribute_set_alloc(2);
    k_buffer_ptr CHALLENGE_KEYTYPE;
    CHALLENGE_KEYTYPE = k_buffer_alloc(NULL, strlen("RSA")+1);
    strcpy((char *)k_buffer_data(CHALLENGE_KEYTYPE), "RSA");
    k_attribute_set_add_attribute(challenge_set, (char *)"CHALLENGE_KEYTYPE", CHALLENGE_KEYTYPE);
    k_attribute_set_add_attribute(challenge_set, (char *)"CHALLENGE_RSA_PUBLIC_KEY", CHALLENGE_RSA_PUBLIC_KEY);
    k_attribute_set_add_attribute(challenge_set, (char *)"SW_ISSUER", SW_ISSUER);

    ret = TRUE;
out:
    if (CHALLENGE_RSA_PUBLIC_KEY) k_buffer_unref(CHALLENGE_RSA_PUBLIC_KEY);
    if (SW_ISSUER) k_buffer_unref(SW_ISSUER);
    if (CHALLENGE_KEYTYPE) k_buffer_unref(CHALLENGE_KEYTYPE);
    if (rsa) RSA_free(rsa);
    return ret;
}
