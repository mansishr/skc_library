#define G_LOG_DOMAIN "keyagent-utils"
#include "internal.h"
#include "k_errors.h"
#include <iostream>
#include <sstream>
#include <openssl/evp.h>


using namespace keyagent;

extern "C"
gchar *
keyagent_generate_checksum(gchar *data, int size)
{
    return g_compute_checksum_for_data (G_CHECKSUM_SHA256, (const guchar *)data, (gsize) size);
}

extern "C" void
keyagent_debug_with_checksum(const gchar *label, unsigned char *buf, unsigned int size)
{
    gchar *tmp =  keyagent_generate_checksum((char *)buf, size);
    std::stringstream ss;
    ss << std::hex << tmp;
    std::string tmp1 = ss.str();
    k_debug_msg("%s %s\n", label, tmp1.c_str());
    g_free(tmp);
}

extern "C" keyagent_buffer_ptr
keyagent_aes_gcm_data_decrypt(keyagent_buffer_ptr msg, keyagent_buffer_ptr key, int tlen, keyagent_buffer_ptr iv)
{
    keyagent_buffer_ptr result;
    EVP_CIPHER_CTX *ctx;
    int outlen, rv;
    int msglen = keyagent_buffer_length(msg) - tlen;
    uint8_t *tag = keyagent_buffer_data(msg) + msglen;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        k_critical_msg("%s() -> Allocating context is failed ! \n", __func__);
        return NULL;
    }

    result = keyagent_buffer_alloc(NULL,msglen);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, keyagent_buffer_length(iv), NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, keyagent_buffer_data(key), keyagent_buffer_data(iv));
    EVP_DecryptUpdate(ctx, keyagent_buffer_data(result), &outlen, keyagent_buffer_data(msg), msglen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tlen, tag);
    rv = EVP_DecryptFinal_ex(ctx, keyagent_buffer_data(result), &outlen);
    EVP_CIPHER_CTX_free(ctx);

    return result;
}