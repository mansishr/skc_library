#define G_LOG_DOMAIN "stm-sw"
#include "key-agent/key_agent.h"
#include "key-agent/stm/stm.h"
#include "config-file/key_configfile.h"
#include "k_errors.h"
#include <glib.h>
#include <errno.h>
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

namespace application_sgx_stm {
    GString *configfile;
    gboolean debug;
    RSA *session_keypair;
    keyagent_buffer_ptr swk;

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

// self validating whether quote contains a valid public key
void
debug_initialize_challenge_from_quote(keyagent_buffer_ptr quote)
{
    keyagent_debug_with_checksum("CLIENT:CKSUM:PEM", keyagent_buffer_data(quote), keyagent_buffer_length(quote));
    BIO* bio = BIO_new_mem_buf(keyagent_buffer_data(quote), keyagent_buffer_length(quote));
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    BIO_free(bio);
}

extern "C" keyagent_buffer_ptr
stm_create_challenge()
{
    BIO_MEM_ptr bio(BIO_new(BIO_s_mem()), ::BIO_free);
    PEM_write_bio_RSA_PUBKEY(bio.get(), application_sgx_stm::session_keypair);
    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(bio.get(), &mem);
    keyagent_buffer_ptr challenge = keyagent_buffer_alloc(mem->data, mem->length);
    //debug_initialize_challenge_from_quote(challenge);
    return challenge;
}

extern "C" void
application_stm_init(const char *config_directory, GError **err)
{
    application_sgx_stm::configfile = g_string_new(g_build_filename(config_directory, "sgx_stm.ini", NULL));
    //void *config = key_config_openfile(application_sgx_stm::configfile->str, err);
    //gchar *server = key_config_get_string(config, "core", "server", err);
    //BIO_MEM_ptr bio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_write(mem, (char *)application_sgx_stm::private_string, strlen(application_sgx_stm::private_string));
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(mem,NULL, NULL, NULL);
    application_sgx_stm::session_keypair = EVP_PKEY_get1_RSA(pkey); // Get the underlying RSA key
    BIO_free(mem);
}


extern "C" gboolean
stm_set_session(keyagent_buffer_ptr session)
{
    gboolean ret = FALSE;
    keyagent_debug_with_checksum("CLIENT:SESSION:PROTECTED", keyagent_buffer_data(session), keyagent_buffer_length(session));

    application_sgx_stm::swk = keyagent_buffer_alloc(NULL, AES_256_KEY_SIZE);

    int result = RSA_private_decrypt(RSA_size(application_sgx_stm::session_keypair),
                                     (const unsigned char *)keyagent_buffer_data(session), keyagent_buffer_data(application_sgx_stm::swk), application_sgx_stm::session_keypair,
                                     RSA_PKCS1_OAEP_PADDING);

    keyagent_debug_with_checksum("CLIENT:SESSION:REAL", keyagent_buffer_data(application_sgx_stm::swk), keyagent_buffer_length(application_sgx_stm::swk));

    if (result == -1) {
        stm_log_openssl_error("Error dencrypting message");
    } else
        ret = TRUE;

    return ret;
}


static
int decrypt(keyagent_buffer_ptr plaintext, keyagent_buffer_ptr key, keyagent_buffer_ptr iv, keyagent_buffer_ptr ciphertext, int tag_len) {
    EVP_CIPHER_CTX *ctx;
    int outlen, rv;
    int msglen = keyagent_buffer_length(ciphertext) - tag_len;
    uint8_t *tag = keyagent_buffer_data(ciphertext) + msglen;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, keyagent_buffer_length(iv), NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, keyagent_buffer_data(key), keyagent_buffer_data(iv));
    EVP_DecryptUpdate(ctx, keyagent_buffer_data(plaintext), &outlen, keyagent_buffer_data(ciphertext), msglen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag);
    rv = EVP_DecryptFinal_ex(ctx, keyagent_buffer_data(plaintext), &outlen);
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}


extern "C" gboolean
stm_load_key(keyagent_keytype type, keyagent_key_attributes_ptr attrs)
{
    stm_wrap_data *wrap_data;
    keyagent_key_attributes_ptr unwrapped_attrs = keyagent_key_alloc_attributes();
    keyagent_buffer_ptr iv, tmp;
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(attrs, IV, iv);
    KEYAGENT_KEY_GET_BYTEARRAY_ATTR(attrs, STM_DATA, tmp);

    wrap_data = (stm_wrap_data *)keyagent_buffer_data(tmp);
    COPY_ATTR_HASH(IV, attrs, unwrapped_attrs);
    COPY_ATTR_HASH(RSA_E, attrs, unwrapped_attrs);
    COPY_ATTR_HASH(RSA_N, attrs, unwrapped_attrs);
    DECRYPT_ATTR_HASH(RSA_D, attrs, unwrapped_attrs, application_sgx_stm::swk, iv, wrap_data->tag_len, decrypt);
    DECRYPT_ATTR_HASH(RSA_P, attrs, unwrapped_attrs, application_sgx_stm::swk, iv, wrap_data->tag_len, decrypt);
    DECRYPT_ATTR_HASH(RSA_Q, attrs, unwrapped_attrs, application_sgx_stm::swk, iv, wrap_data->tag_len, decrypt);
    DECRYPT_ATTR_HASH(RSA_DP, attrs, unwrapped_attrs, application_sgx_stm::swk, iv, wrap_data->tag_len, decrypt);
    DECRYPT_ATTR_HASH(RSA_DQ, attrs, unwrapped_attrs, application_sgx_stm::swk, iv, wrap_data->tag_len, decrypt);
    DECRYPT_ATTR_HASH(RSA_QINV, attrs, unwrapped_attrs, application_sgx_stm::swk, iv, wrap_data->tag_len, decrypt);

    return TRUE;
}