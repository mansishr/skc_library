#define G_LOG_DOMAIN "stm-sw"
#include "key-agent/key_agent.h"
#include "key-agent/stm/stm.h"
#include "config-file/key_configfile.h"
#include "k_errors.h"
#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <iostream>
#include <memory>
#include "internal.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>

using namespace std;


using BIO_MEM_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

namespace application_sw_stm {
    GString *configfile;
    gboolean debug;
    RSA *session_keypair;
    k_buffer_ptr sw_issuer;
    k_buffer_ptr swk;

    static const gchar *private_string = \
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCaQP6TCVuya/JR"
"g4G5WTJYPIE3EZA0mspRm73tn6EEbc4Dzl9jqhUJ3KhP4oOa0AWBOBjvopGQdVhA"
"fcdgWl5zm82m0sk13o5UkJdHo0VRHZvtocuSt6yrI8ysAc1TXrCnzmp0cAs13vYS"
"hQ+RUi0epoE6V3Hsn2/JQXdukBarhfFGVuIr2K9i5yLj+OvimlGiyjotmb0ifObn"
"fNi3YCodRlD7daAr5zNnKTy0sYQ3uu0tnuim9UBoCJEZaJRYAK1HCakCrYvk+5Zm"
"Rh1DtZCKCTHlzfHyIGR4SHTbbOpiQY5OHZR7hR+shi5KqMtvZ36OR9lDVLgtAtA+"
"0zE1X8WrAgMBAAECggEAWybDCJJEHGgLdj22v5dE171RQgBf7aX2nkjg7/UfSiW0"
"0qz100gjTIOW9jXNPQNl7Vj/60NuryWYc+ufkIF2ROyxlr4CZpHQG4qhypRhlrBf"
"fwnX6Sgeobby8EXUVkqjK1YftBStmzTYxlLYwzADN5R+0sHvsTr57LyB3dTJgKsn"
"4iAuJXfR4EthZ6iEM+D8FrmXt5lJ2d1FoMLKiC09M7nMuY9ARqR6O5Tr/Tq4vqfw"
"La6Mv3mWrD2nIznyTJtxUkAxvCRi1tfHOw2YCl6u2JqqWRjLBeaGNyydhGeVH5PT"
"utPHtDciCxpUgGuQ8wNBEstiGYXklpLJFS48+bWVCQKBgQDLC4DNeZ/Tc9g+WUFU"
"ypVCTKfCYt2YmLcNeKDqIPdt14PmV3odIxZGJ1OWrNK1LA50pet0xxY1HRjcBsN+"
"XUIc5Xa/0nWazdz7c0nqzZgOpVYfPcApQ1K/dqsoWzRY+rlz2PEOYJwMaKW/kkVV"
"8EPEg38Ck/qr5iKsBYljTteHhQKBgQDCe+iKtPjlFPJ4WX8vTu5QVpRjYmqj87/j"
"4JFpSh7Lv2PsxSCGQR/7JoyB8Zaz9dyP+RV8/ySJuwGqSseU+W495h8oHe1DtIxU"
"lTR1GB4YI4BU+txvydzQiaFyEUdEFqJblCxXg+XDAcwCUYESLbR661ljbVV/0Qep"
"HMTeXgfnbwKBgDPMYHSK1ZItGHp3bKpD8CX0xktZy2xVcUV3g52XAWg9NcH6iQWL"
"4O/Oso1a03oynhF2DoZBD9JG9QOUmiTPh8E1bMDs4OG4KOrg83d6MZNy7HCV4ULl"
"kOOVU369HbKha9Q5AO4JCWZFABvKJfQRkkg8v5cZxzY5RJkb5Hu4LlW9AoGACvxg"
"2GT8okQapj23934n7BXX7/1BNN2x+zdWP3JWZv/6rwc7nRnUqqU0zqpM7wF2YhOZ"
"6SOodrc/ktUCjSHB3nE/VU7LdkWen7CF9A9Ws9pdh29cQFxQwt7jZcQgGHKG3VFz"
"Z8Yllmxlj8P23IYEaeUdeYZVjBDMs/rSDBWXsLUCgYEAw4TTKH/4BdnRIKhNLp63"
"n8oGo7Cc/idSQD8XbUVpPbLmychOs2no3Y0XT+xRTAuXjm0GYdmY3Sk3/polGMu5"
"NHmi5293eAxJ+9ikSD+bYCaLCXFI2PmgJkm+uS1WucqQOSAKOXS6mfsv2pn9YXKw"
"QCMIqX4p7BmO7OD1CFEu6ho=\n"
"-----END PRIVATE KEY-----";
}

extern "C" void
application_stm_init(const char *config_directory, GError **err)
{
    gint  init_delay = 0;

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    application_sw_stm::configfile = g_string_new(g_build_filename(config_directory, "sw_stm.ini", NULL));
    void *config = key_config_openfile(application_sw_stm::configfile->str, err);
    application_sw_stm::sw_issuer = k_buffer_alloc(NULL, STM_ISSUER_SIZE);
    if (config) {
        init_delay = key_config_get_integer_optional(config, "testing", "initdelay", 0);
        char *tmp = key_config_get_string_optional(config, "core", "issuer", "Intel-1");
        memcpy(k_buffer_data(application_sw_stm::sw_issuer), tmp, strlen(tmp));
        g_free(tmp);
    }
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_write(mem, (char *)application_sw_stm::private_string, strlen(application_sw_stm::private_string));
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(mem,NULL, NULL, NULL);
    application_sw_stm::session_keypair = EVP_PKEY_get1_RSA(pkey); // Get the underlying RSA key
    BIO_free(mem);

    if (init_delay)
        sleep(init_delay);
}

extern "C" gboolean
application_stm_activate(GError **err)
{
    return TRUE;
}

// self validating whether quote contains a valid public key
void
debug_initialize_challenge_from_quote(k_buffer_ptr quote)
{
    k_debug_generate_checksum("CLIENT:CKSUM:PEM", k_buffer_data(quote), k_buffer_length(quote));
    BIO* bio = BIO_new_mem_buf(k_buffer_data(quote) + STM_ISSUER_SIZE, k_buffer_length(quote) - STM_ISSUER_SIZE);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    BIO_free(bio);
}

extern "C" gboolean
stm_create_challenge(k_buffer_ptr *challenge, GError **err)
{
    BIO_MEM_ptr bio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_write(bio.get(), k_buffer_data(application_sw_stm::sw_issuer), STM_ISSUER_SIZE);
    PEM_write_bio_RSA_PUBKEY(bio.get(), application_sw_stm::session_keypair);
    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(bio.get(), &mem);

    *challenge = k_buffer_alloc(mem->data, mem->length);
    //debug_initialize_challenge_from_quote(challenge);
    return TRUE;
}


extern "C" gboolean
stm_set_session(keyagent_stm_session_details *details, GError **error)
{
    gboolean ret = FALSE;
    k_debug_generate_checksum("CLIENT:SESSION:PROTECTED", k_buffer_data(details->session), k_buffer_length(details->session));

	application_sw_stm::swk = k_buffer_alloc(NULL, details->swk_size_in_bits/8);

    int result = RSA_private_decrypt(RSA_size(application_sw_stm::session_keypair),
                     (const unsigned char *)k_buffer_data(details->session), k_buffer_data(application_sw_stm::swk), application_sw_stm::session_keypair,
                                     RSA_PKCS1_OAEP_PADDING);

    k_debug_generate_checksum("CLIENT:SESSION:REAL", k_buffer_data(application_sw_stm::swk), k_buffer_length(application_sw_stm::swk));

    if (result == -1) {
        stm_log_openssl_error("Error dencrypting message");
    } else
        ret = TRUE;

    return ret;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L

extern "C" {
void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}

void RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}


int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
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

int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
    /* If the fields p and q in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->p == NULL && p == NULL)
        || (r->q == NULL && q == NULL))
        return 0;

    if (p != NULL) {
        BN_free(r->p);
        r->p = p;
    }
    if (q != NULL) {
        BN_free(r->q);
        r->q = q;
    }

    return 1;
}

int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->dmp1 == NULL && dmp1 == NULL)
        || (r->dmq1 == NULL && dmq1 == NULL)
        || (r->iqmp == NULL && iqmp == NULL))
        return 0;

    if (dmp1 != NULL) {
        BN_free(r->dmp1);
        r->dmp1 = dmp1;
    }
    if (dmq1 != NULL) {
        BN_free(r->dmq1);
        r->dmq1 = dmq1;
    }
    if (iqmp != NULL) {
        BN_free(r->iqmp);
        r->iqmp = iqmp;
    }

    return 1;
}
};

#endif

static void
test_rsa_wrapped_key(EVP_PKEY *pkey, k_attributes_ptr attrs)
{
    RSA *rsa_key = EVP_PKEY_get1_RSA(pkey);

    if (!rsa_key)
        return;

    k_buffer_ptr STM_TEST_DATA;
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(attrs, STM_TEST_DATA, STM_TEST_DATA);
    k_buffer_ptr STM_TEST_SIG;
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(attrs, STM_TEST_SIG, STM_TEST_SIG);

    k_debug_msg("rsa_sig %p %s\n", rsa_key,
        (RSA_verify(NID_sha1, k_buffer_data(STM_TEST_DATA), k_buffer_length(STM_TEST_DATA),
        k_buffer_data(STM_TEST_SIG),
        k_buffer_length(STM_TEST_SIG), rsa_key) == 1 ? "PASSED" : "FAILED"));

    RSA_free(rsa_key);
}

static void
test_ecc_wrapped_key(EVP_PKEY *pkey, k_attributes_ptr attrs)
{
    EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pkey);

    if (!eckey)
        return;

    const unsigned char *data = NULL;
    int len = 0;

    k_buffer_ptr STM_TEST_DATA;
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(attrs, STM_TEST_DATA, STM_TEST_DATA);
    k_buffer_ptr STM_TEST_SIG;
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(attrs, STM_TEST_SIG, STM_TEST_SIG);
    ECDSA_SIG* _sig = NULL;
    data = k_buffer_data(STM_TEST_SIG);
    len = k_buffer_length(STM_TEST_SIG);
    _sig =  d2i_ECDSA_SIG(NULL, &data, len);
    k_debug_msg("ec_sig %p %s\n", _sig,
        (ECDSA_do_verify(k_buffer_data(STM_TEST_DATA), k_buffer_length(STM_TEST_DATA), _sig, eckey) == 1 ? "PASSED" : "FAILED"));

    EC_KEY_free(eckey);

}

extern "C" gboolean
stm_load_key(keyagent_stm_loadkey_details *details, GError **error)
{
    gboolean ret = FALSE;
    k_buffer_ptr tmp = NULL;
    k_buffer_ptr iv = NULL;
    k_buffer_ptr wrapped_key = NULL;
    k_buffer_ptr pkcs8 = NULL;
    keyagent_keytransfer_t *keytransfer = NULL;
    k_buffer_ptr keydata = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    EVP_PKEY *pkey = NULL;
    const unsigned char *tmpp = NULL;

    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(details->attrs, KEYDATA, tmp);
    k_debug_generate_checksum("STM:CMS", k_buffer_data(tmp), k_buffer_length(tmp));


    if (!KEYAGENT_STM_OP(&details->cbs,verify_and_extract_cms_message)(tmp, &keydata, error))
        goto out;

    k_debug_generate_checksum("STM:PAYLOAD", k_buffer_data(keydata), k_buffer_length(keydata));

    keytransfer = (keyagent_keytransfer_t *)k_buffer_data(keydata);
    iv = k_buffer_alloc(k_buffer_data(keydata) + sizeof(keyagent_keytransfer_t),  keytransfer->iv_length);
    wrapped_key = k_buffer_alloc(k_buffer_data(keydata) + sizeof(keyagent_keytransfer_t) + 
        keytransfer->iv_length, keytransfer->wrap_size);
    k_debug_generate_checksum("STM:IV", k_buffer_data(iv), k_buffer_length(iv));
    k_debug_generate_checksum("STM:PKCS8:WRAPPED", k_buffer_data(wrapped_key), k_buffer_length(wrapped_key));

    pkcs8 = KEYAGENT_STM_OP(&details->cbs,aes_decrypt)(details->swk_quark, wrapped_key, application_sw_stm::swk, keytransfer->tag_size, iv);
    k_debug_generate_checksum("STM:PKCS8", k_buffer_data(pkcs8), k_buffer_length(pkcs8));
    tmpp = k_buffer_data(pkcs8);
    p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &tmpp,  k_buffer_length(pkcs8));

    if (!p8inf)
        goto out;

    if (details->apimodule_ops.apimodule_func_loadkey) {
        keyagent_apimodule_loadkey_details apimodule_details;
        apimodule_details.type = details->type;
        apimodule_details.key = pkcs8;
        apimodule_details.url = details->url;
        (details->apimodule_ops.apimodule_func_loadkey)(&apimodule_details, error);
		if( *error )
		{
			k_set_error (error, STM_ERROR_API_MODULE_LOADKEY, 
				"API Module loadkey error");
			goto out;
		}
    }
        
    pkey = EVP_PKCS82PKEY(p8inf);
	if(pkey == NULL)
	{
		goto out;
	}

    switch (details->type) {
    case KEYAGENT_RSAKEY:
        test_rsa_wrapped_key(pkey, details->attrs);
        break;
    case KEYAGENT_ECKEY:
        test_ecc_wrapped_key(pkey, details->attrs);
        break;
    }
    ret = TRUE;
out:
    if (p8inf) PKCS8_PRIV_KEY_INFO_free(p8inf);
    if (pkey)  EVP_PKEY_free(pkey);
    k_buffer_unref(keydata);
    k_buffer_unref(wrapped_key);
    k_buffer_unref(pkcs8);
    k_buffer_unref(tmp);
    k_buffer_unref(iv);
    return ret;
}

extern "C" gboolean
stm_seal_key(keyagent_keytype type, k_attributes_ptr attrs, k_buffer_ptr *sealed_data, GError **error)
{
    return FALSE;
}

extern "C" gboolean
stm_unseal_key(keyagent_keytype type, k_buffer_ptr sealed_data, k_attributes_ptr *wrapped_attrs, GError **error)
{
    return FALSE;
}
