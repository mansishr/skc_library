#define G_LOG_DOMAIN "keyagent-utils"
#include "internal.h"
#include "k_errors.h"
#include <iostream>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/err.h>

using namespace keyagent;

extern "C" k_buffer_ptr
__keyagent_aes_decrypt(GQuark swk_type, k_buffer_ptr msg, k_buffer_ptr key, int tlen, k_buffer_ptr iv)
{
    swk_type_op *op = (swk_type_op *)g_hash_table_lookup(keyagent::swk_type_hash, GUINT_TO_POINTER(swk_type));
    if (op == NULL || op->cipher_func == NULL || op->decrypt_func == NULL) {
        k_critical_msg("%s() -> Enable to fetch AES function from the hash ! \n", __func__);
        return NULL;
	}
	return op->decrypt_func(op, msg, key, tlen, iv);

}
extern "C" int
__keyagent_get_swk_size( GQuark swk_type )
{
    swk_type_op *op = (swk_type_op *)g_hash_table_lookup(keyagent::swk_type_hash, GUINT_TO_POINTER(swk_type));
    if (op == NULL ) {
        k_critical_msg("%s() -> Enable to fetch AES function from the hash ! \n", __func__);
	    return -1;	
	}
	return op->keybits;
}

extern "C" k_buffer_ptr
aes_gcm_decrypt(swk_type_op *op, k_buffer_ptr msg, k_buffer_ptr key, int tlen, k_buffer_ptr iv)
{
    CRYPTO_malloc_init();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

	k_buffer_ptr result;
    EVP_CIPHER_CTX *ctx;
    int outlen, rv;
    int msglen = k_buffer_length(msg) - tlen;
    uint8_t *tag = k_buffer_data(msg) + msglen;
	k_debug_msg("AES:GCM:-keybit:%d\n", op->keybits);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        k_critical_msg("%s() -> Allocating context is failed ! \n", __func__);
        return NULL;
    }

    result = k_buffer_alloc(NULL,msglen);

	EVP_DecryptInit_ex(ctx, op->cipher_func(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, k_buffer_length(iv), NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, k_buffer_data(key), k_buffer_data(iv));
    EVP_DecryptUpdate(ctx, k_buffer_data(result), &outlen, k_buffer_data(msg), msglen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tlen, tag);
    rv = EVP_DecryptFinal_ex(ctx, k_buffer_data(result), &outlen);
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

extern "C" k_buffer_ptr
aes_cbc_decrypt(swk_type_op *op, k_buffer_ptr msg, k_buffer_ptr key, int tlen, k_buffer_ptr iv)
{
    CRYPTO_malloc_init();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

	k_buffer_ptr result;
    EVP_CIPHER_CTX *ctx;
    int outlen, rv;
	int msglen = k_buffer_length(msg);
    uint8_t *tag = k_buffer_data(msg) + msglen;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        k_critical_msg("%s() -> Allocating context is failed ! \n", __func__);
        return NULL;
    }

	k_debug_msg("AES:CBC-keybit:%d\n", op->keybits);
    result = k_buffer_alloc(NULL,msglen);

    EVP_DecryptInit_ex(ctx, op->cipher_func(), NULL, k_buffer_data(key), k_buffer_data(iv));
    EVP_DecryptUpdate(ctx, k_buffer_data(result), &outlen, k_buffer_data(msg), msglen);
	msglen = outlen;
    rv = EVP_DecryptFinal_ex(ctx, k_buffer_data(result)+outlen , &outlen);
	msglen += outlen;
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

static X509_STORE *
cms_setup_verify()
{
    X509_STORE *store;
    X509_LOOKUP *lookup;

    if (!(store = X509_STORE_new()))
        goto end;

    if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())))
        goto end;

    X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
    if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir())))
        goto end;

    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
    ERR_clear_error();
    return store;
 end:
    X509_STORE_free(store);
    return NULL;
}

extern "C" int 
cms_cb(int ok, X509_STORE_CTX *ctx)
{
    int error;
    error = X509_STORE_CTX_get_error(ctx);
    if ((error != X509_V_ERR_NO_EXPLICIT_POLICY)
        && ((error != X509_V_OK) || (ok != 2)))
        return ok;
    return ok;
}

extern "C" gboolean
__keyagent_verify_and_extract_cms_message(k_buffer_ptr msg, k_buffer_ptr *data, GError **error)
{
    X509_STORE *store = NULL;
    CMS_ContentInfo *verify_cms = NULL;
    BIO *input_bio = NULL;
    BIO *result_bio = NULL;
    int flags = (CMS_PARTIAL | CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY);
    gboolean ret = FALSE;
    BUF_MEM *bptr = 0;

    flags &= ~CMS_DETACHED;

    input_bio = BIO_new(BIO_s_mem());
    BIO_write(input_bio, k_buffer_data(msg), k_buffer_length(msg));
    if (!(verify_cms = d2i_CMS_bio(input_bio, NULL))) {
        k_set_error (error, KEYAGENT_ERROR_BADCMS_MSG,
            "%s: %s", __func__, "The input msg cann't be converted into cms");
        goto out;
    }
    if (!(store = cms_setup_verify())) {
        k_set_error (error, KEYAGENT_ERROR_BADCMS_MSG,
            "%s: %s", __func__, "Cannot initialize cms verify");
        goto out;
    }
    X509_STORE_set_verify_cb(store, cms_cb);
    result_bio = BIO_new(BIO_s_mem());
    if (CMS_verify(verify_cms, NULL, store, NULL, result_bio, flags) != 1) {
        k_set_error (error, KEYAGENT_ERROR_BADCMS_MSG,
            "%s: %s", __func__, "cms message failed to verify");
    }
    BIO_get_mem_ptr(result_bio, &bptr);
    *data = k_buffer_alloc(bptr->data, bptr->length);
    ret = TRUE;
out:
    if (store) X509_STORE_free(store);
    if (input_bio) BIO_free(input_bio);
    if (result_bio) BIO_free(result_bio);
    if (verify_cms) CMS_ContentInfo_free(verify_cms);
    return ret;
}
