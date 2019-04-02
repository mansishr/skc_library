#define G_LOG_DOMAIN "npm-kms"
#include <glib.h>
#include "k_types.h"
#include "k_errors.h"
#include <openssl/evp.h>
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/err.h>

DLL_LOCAL X509_STORE * 
__cms_setup_verify()
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

extern "C" int  DLL_LOCAL
cms_cb(int ok, X509_STORE_CTX *ctx)
{
    int error;
    error = X509_STORE_CTX_get_error(ctx);
    if ((error != X509_V_ERR_NO_EXPLICIT_POLICY)
        && ((error != X509_V_OK) || (ok != 2)))
        return ok;
    return ok;
}

extern "C" gboolean DLL_LOCAL
verify_and_extract_cms_message(k_buffer_ptr msg, k_buffer_ptr *data, GError **error)
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
        k_set_error (error, -1,
            "%s: %s", __func__, "The input msg cann't be converted into cms");
        goto out;
    }
    if (!(store = __cms_setup_verify())) {
        k_set_error (error, -1,
            "%s: %s", __func__, "Cannot initialize cms verify");
        goto out;
    }
    X509_STORE_set_verify_cb(store, cms_cb);
    result_bio = BIO_new(BIO_s_mem());
    if (CMS_verify(verify_cms, NULL, store, NULL, result_bio, flags) != 1) {
        k_set_error (error, -1,
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
