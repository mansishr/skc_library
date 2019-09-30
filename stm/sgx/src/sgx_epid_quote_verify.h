#ifndef __SGX_EPID_QUOTE_VERIFY_H__
#define __SGX_EPID_QUOTE_VERIFY_H__

#include <stdio.h>
#include <glib.h>
#include <stdint.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <exception>
#include <jsoncpp/json/json.h>
#include <string>
#include "utils/utils.h"


typedef struct {
        //INPUT DATA
        k_buffer_ptr quote;
        //OUTPUT DATA
        GString *isv_enclave_quote_status;
        GString *id;
        GString *version;
        GString *timestamp;
        GString *isv_enclave_quote_body;
        GString *ias_signing_cert;
        GString *ias_report_sign;
        k_buffer_ptr res_data;
        X509 **cert_chain;
}epid_report_data;

typedef struct {
        //INPUT DATA
        uint32_t gid;
        //OUTPUT DATA
        k_buffer_ptr sigrl;
}epid_sigrl_data;


typedef struct {
        gboolean debug;
        gint https_response_code;
        keyagent_ssl_opts ssl_opts;
        union {
                epid_sigrl_data sigrl;
                epid_report_data report;
        }data;
}sgx_quote_epid;



#ifdef  __cplusplus
namespace stmsgx_epid_ssl_data{
	extern  gchar *ias_base_url;
	extern  gchar *ias_version;
	extern  gchar *ias_cacert;
	extern  gchar *ias_sub_key;
	extern  gchar *cacert;
	extern  gchar *proxy;
	extern  gboolean verify;
	extern  X509_STORE *store;
}
#endif



#define k_string_free(string, flag) { if(string) { g_string_free((string), flag); string=NULL;}}
gboolean stmsgx_put_ias_signing_cert_to_store(char *ias_cacert_path, GError **error);
gboolean stmsgx_get_extended_epid_group_id(uint32_t *e_gid);
gboolean stmsgx_get_epid_sigrl(sgx_quote_epid *epid, GError **err);
gboolean stmsgx_epid_quote_verify(sgx_quote_epid *epid,  GError **err);
void stmsgx_clear_epid_report_data(sgx_quote_epid *epid);
void stmsgx_clear_epid_sigrl_data(sgx_quote_epid *epid);
void set_quote_verify_ssl_options(keyagent_ssl_opts *ssl_opts);
#endif
