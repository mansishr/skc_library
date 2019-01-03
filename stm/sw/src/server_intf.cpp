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

extern "C" gboolean
stm_challenge_generate_request(const gchar **request, GError **error)
{
    g_return_val_if_fail(request != NULL, FALSE);
    stm_uuid uuid;
    uuid_generate_v4 (&uuid);
    *request = uuid_to_string (&uuid);
    return TRUE;
}

extern "C" gboolean
stm_challenge_verify(k_buffer_ptr quote, keyagent_attribute_set_ptr *challenge_attrs, GError **error)
{
    gboolean ret = FALSE;
    k_buffer_ptr CHALLENGE_RSA_PUBLIC_KEY = NULL;
    k_buffer_ptr SW_ISSUER = NULL;
    BIO* bio = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    int len = 0;
    unsigned char *tmp = NULL;
    keyagent_attribute_set_ptr challenge_set = NULL;

    k_buffer_ptr CHALLENGE_KEYTYPE;
    CHALLENGE_KEYTYPE = k_buffer_alloc(NULL, strlen("RSA")+1);
    strcpy((char *)k_buffer_data(CHALLENGE_KEYTYPE), "RSA");

    *challenge_attrs = NULL;

    bio = BIO_new_mem_buf(k_buffer_data(quote), k_buffer_length(quote));
    SW_ISSUER = k_buffer_alloc(NULL, STM_ISSUER_SIZE);
    BIO_read(bio, k_buffer_data(SW_ISSUER), k_buffer_length(SW_ISSUER));
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    rsa = EVP_PKEY_get1_RSA(pkey);
    BIO_free(bio);
    bio = NULL;

    BIO_MEM_ptr mbio(BIO_new(BIO_s_mem()), ::BIO_free);
    i2d_RSA_PUBKEY_bio(mbio.get(), rsa);
    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(mbio.get(), &mem);
    CHALLENGE_RSA_PUBLIC_KEY = k_buffer_alloc(mem->data, mem->length);

    *challenge_attrs = challenge_set = keyagent_attribute_set_alloc(3);
    keyagent_attribute_set_add_attribute(challenge_set, (char *)"CHALLENGE_KEYTYPE", CHALLENGE_KEYTYPE);
    keyagent_attribute_set_add_attribute(challenge_set, (char *)"CHALLENGE_RSA_PUBLIC_KEY", CHALLENGE_RSA_PUBLIC_KEY);
    keyagent_attribute_set_add_attribute(challenge_set, (char *)"SW_ISSUER", SW_ISSUER);

    ret = TRUE;
out:
    if (CHALLENGE_RSA_PUBLIC_KEY) k_buffer_unref(CHALLENGE_RSA_PUBLIC_KEY);
    if (SW_ISSUER) k_buffer_unref(SW_ISSUER);
    if (CHALLENGE_KEYTYPE) k_buffer_unref(CHALLENGE_KEYTYPE);
    if (pkey) EVP_PKEY_free(pkey);
    if (rsa) RSA_free(rsa);
    return ret;
}
