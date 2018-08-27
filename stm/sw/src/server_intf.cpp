#define G_LOG_DOMAIN "stm-sw"
#include "key-agent/key_agent.h"
#include "key-agent/stm/stm.h"
#include "config-file/key_configfile.h"
#include "k_errors.h"
#include <glib.h>
#include <glib/gi18n.h>
#include <errno.h>
#include <iostream>
#include <memory>
#include "internal.h"
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>

using namespace std;

namespace server_sgx_stm {
    keyagent_buffer_ptr swk;
}

extern "C" void
server_stm_init(const char *config_directory, GError **err)
{
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

extern "C" const gchar *
stm_challenge_generate_request()
{
  stm_uuid uuid;
  uuid_generate_v4 (&uuid);
  return uuid_to_string (&uuid);
}

extern "C" keyagent_buffer_ptr
stm_challenge_verify(keyagent_buffer_ptr quote)
{
    BIO* bio = BIO_new_mem_buf(keyagent_buffer_data(quote), keyagent_buffer_length(quote));
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    BIO_free(bio);

    keyagent_buffer_ptr encrypted_swk = NULL;
    int encrypt_len;

   	if (server_sgx_stm::swk) keyagent_buffer_unref(server_sgx_stm::swk);
    server_sgx_stm::swk = keyagent_buffer_alloc(NULL, AES_256_KEY_SIZE);

    if (!RAND_bytes((unsigned char *)keyagent_buffer_data(server_sgx_stm::swk), keyagent_buffer_length(server_sgx_stm::swk))) {
        k_critical_msg("RAND_bytes error: %s", strerror(errno));
        goto errexit;
    }

    // Encrypt the swk
    encrypted_swk = keyagent_buffer_alloc(NULL, RSA_size(rsa));
    encrypt_len = RSA_public_encrypt(keyagent_buffer_length(server_sgx_stm::swk), keyagent_buffer_data(server_sgx_stm::swk), keyagent_buffer_data(encrypted_swk), rsa, RSA_PKCS1_OAEP_PADDING);

    if (encrypt_len != -1)
        goto out;

    stm_log_openssl_error("Error encrypting message");
    errexit:
    if (encrypted_swk) keyagent_buffer_unref(encrypted_swk);
    encrypted_swk = NULL;

    out:
    if (pkey) EVP_PKEY_free(pkey);
    if (rsa) RSA_free(rsa);

    return encrypted_swk;
}

static
int encrypt(keyagent_buffer_ptr plaintext, keyagent_buffer_ptr key, keyagent_buffer_ptr iv, keyagent_buffer_ptr ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    assert(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1);
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, keyagent_buffer_length(iv), NULL) == 1);
    assert(EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char *)keyagent_buffer_data(key), (unsigned  char *)keyagent_buffer_data(iv)) == 1);
    assert(EVP_EncryptUpdate(ctx, keyagent_buffer_data(ciphertext), &len, keyagent_buffer_data(plaintext), keyagent_buffer_length(plaintext)) == 1);
    ciphertext_len = len;
    assert(EVP_EncryptFinal_ex(ctx, keyagent_buffer_data(ciphertext) + len, &len) == 1);
    ciphertext_len += len;
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, (unsigned char *) keyagent_buffer_data(ciphertext) + ciphertext_len) == 1);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

extern "C" keyagent_key_attributes_ptr
stm_wrap_key(keyagent_keytype type, keyagent_key_attributes_ptr attrs)
{
    keyagent_key_attributes_ptr wrapped_attrs = keyagent_key_alloc_attributes();
    keyagent_buffer_ptr iv;
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(attrs, IV, iv);

    COPY_ATTR_HASH(IV, attrs, wrapped_attrs);
    COPY_ATTR_HASH(RSA_E, attrs, wrapped_attrs);
    COPY_ATTR_HASH(RSA_N, attrs, wrapped_attrs);
    ENCRYPT_ATTR_HASH(RSA_D, attrs, wrapped_attrs, server_sgx_stm::swk, iv, encrypt);
    ENCRYPT_ATTR_HASH(RSA_P, attrs, wrapped_attrs, server_sgx_stm::swk, iv, encrypt);
    ENCRYPT_ATTR_HASH(RSA_Q, attrs, wrapped_attrs, server_sgx_stm::swk, iv, encrypt);
    ENCRYPT_ATTR_HASH(RSA_DP, attrs, wrapped_attrs, server_sgx_stm::swk, iv, encrypt);
    ENCRYPT_ATTR_HASH(RSA_DQ, attrs, wrapped_attrs, server_sgx_stm::swk, iv, encrypt);
    ENCRYPT_ATTR_HASH(RSA_QINV, attrs, wrapped_attrs, server_sgx_stm::swk, iv, encrypt);

    stm_wrap_data wrap_data;
    wrap_data.tag_len = TAG_SIZE;

    keyagent_buffer_ptr STM_DATA = keyagent_buffer_alloc(NULL, sizeof(stm_wrap_data));
    memcpy(keyagent_buffer_data(STM_DATA), &wrap_data, sizeof(stm_wrap_data));
    KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(wrapped_attrs, STM_DATA);
	keyagent_buffer_unref(STM_DATA);
    return wrapped_attrs;
}
