#define G_LOG_DOMAIN "SGX-ECDSA-ATTESTATION"

#include "sgx_ecdsa_quote_verify.h"
#include "k_errors.h"

#include <glib.h>
#include <glib/gi18n.h>
#include <errno.h>
#include <iostream>
#include <fstream>
#include <memory>
#include "internal.h"
#include "include/k_debug.h"
#include <stdio.h>

#include <QuoteVerification.h>
#include "curl/curl.h"
#include "utils/utils.h"
#include <jsoncpp/json/json.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/conf.h>

#include <sgx_quote.h>

#include <regex>
#include <string.h>
#include<vector>

using namespace std;


template<typename T>
inline auto make_unique(T*) -> std::unique_ptr<T, void(*)(T*)>;

static inline void freeSTACK_OF_ASN1TYPE(STACK_OF(ASN1_TYPE)* asn1type_stack)
{
    sk_ASN1_TYPE_pop_free(asn1type_stack, ASN1_TYPE_free);
}

using STACK_OF_ASN1TYPE_uptr        = std::unique_ptr<STACK_OF(ASN1_TYPE),      decltype(&freeSTACK_OF_ASN1TYPE)>;

template<>
inline STACK_OF_ASN1TYPE_uptr make_unique(STACK_OF(ASN1_TYPE)* raw_pointer)
{
    return STACK_OF_ASN1TYPE_uptr(raw_pointer, freeSTACK_OF_ASN1TYPE);
}

gboolean fetchTCBInfo(GString* url, const char* fmspc, k_buffer_ptr& return_data)
{
	gboolean ret = FALSE;
	gint res_https_code = -1;
	GString* tcbinfo_url = g_string_new(url->str);
	g_string_append(url,fmspc); 
	k_debug_msg("url to fetch TCBINFO: %s", url->str);
	GPtrArray * res_headers = g_ptr_array_new ();

	res_https_code = skc_https_send(url, NULL, NULL, res_headers, return_data, NULL,NULL, true);
	if( res_https_code == -1 || res_https_code == 0)
	{
	     k_info_msg("failed to get TCBInfo: status:%d\n", res_https_code);
	     goto out;
	}
	if( res_https_code != 200)
	{
		k_info_msg("failed to get TCBInfo: status:%d", res_https_code);
		goto out;
	}
	ret = TRUE;

    out:
	g_string_free(url, TRUE);
	g_ptr_array_free(res_headers, TRUE);
	return ret;
}

gboolean fetchIntermediateCRL(const char* intermediate_url, k_buffer_ptr& return_data)
{
	gboolean ret = FALSE;
	gint res_https_code = -1;
	GString * url = g_string_new(intermediate_url);
	k_debug_msg("intermediate_url: %s", intermediate_url);
	res_https_code = skc_https_send(url, NULL, NULL, NULL, return_data, NULL,NULL, true);
	if( res_https_code == -1 || res_https_code == 0)
	{
	     k_info_msg("failed to get intermediateCACRL: status:%d\n", res_https_code);
	     goto out;
	}
	if( res_https_code != 200) {
		k_info_msg("failed to get TCBInfo: intermediateCACRL:%d", res_https_code);
		goto out;
	}
	ret = TRUE;
    out:
	    if (url) g_string_free(url, TRUE);
	    return ret;
}

/**
 * Brief: This API is use to fetch FMSPC value from PCK Certificate file.
 * SGX Extensions are customised extensions in PEM File. The extension looks like:
 * <SGX Extensions OID>:
 * <PPID OID>: <PPID value>
 * <TCB OID>:
 * <SGX TCB Comp01 SVN OID>: <SGX TCB Comp01 SVN value>
 * <SGX TCB Comp02 SVN OID>: <SGX TCB Comp02 SVN value>
 * …
 * <SGX TCB Comp16 SVN OID>: <SGX TCB Comp16 SVN value>
 * <PCESVN OID>: <PCESVN value>
 * <CPUSVN OID>: <CPUSVN value>
 * <PCE-ID OID>: <PCE-ID value>
 * <FMSPC OID>: <FMSPC value> - THIS WE NEED TO GET.
 * <SGX Type OID>: <SGX Type value>
 * For getting this first we get to SGX EXtensions. Then we put the data in a vector( vecPtr)
 * Now again parse the vector and get the data in a stack(each OID with its value)(sgx_stack)
 * For each of the entries we need entry number 3(FMSPC)(oidTupleWrapper). Fetch that.
 * For more please go through https://download.01.org/intel-sgx/dcap-1.0.1/docs/SGX_PCK_Certificate_CRL_Spec-1.0.pdf
 */
void getFMSPC(X509* certX509, std::string& fmspcVal)
{
	///Retrying to get fmspc
	const int extsCount = X509_get_ext_count(certX509);
	std::string fmspc;
	STACK_OF(X509_EXTENSION) *exts = certX509->cert_info->extensions;
	for (int i=0; i < extsCount; i++) {
		X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
		const ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
		const int nid = OBJ_obj2nid(obj);
		///Since SGX extension is customized extension hence it will be under NID_undef.
		if(nid == NID_undef) {
			const auto sgx_extension_data = X509_EXTENSION_get_data(ex);
			std::vector<uint8_t> sgx_extension_vec(static_cast<size_t>(sgx_extension_data->length));
			std::copy_n(sgx_extension_data->data, sgx_extension_data->length, sgx_extension_vec.begin());
			const auto *vecPtr = sgx_extension_vec.data();
			const ASN1_TYPE* sequence = d2i_ASN1_TYPE(nullptr, &vecPtr, sgx_extension_data->length);
			///Now after coing to sgx extensions we are getting to the data in all OIDs.
			const unsigned char *oid_data = sequence->value.sequence->data;
			auto sgx_stack = make_unique(d2i_ASN1_SEQUENCE_ANY(nullptr, &oid_data, sequence->value.sequence->length));
			const auto stackEntries = sk_ASN1_TYPE_num(sgx_stack.get());
			const auto oidTupleWrapper = sk_ASN1_TYPE_value(sgx_stack.get(), 3);
			const unsigned char *fmspcPtr = oidTupleWrapper->value.sequence->data;
			auto fmspc_stack = make_unique(d2i_ASN1_SEQUENCE_ANY(nullptr, &fmspcPtr, oidTupleWrapper->value.sequence->length));
			const auto oidTupleEntries = sk_ASN1_TYPE_num(fmspc_stack.get());
			const auto oidName = sk_ASN1_TYPE_value(fmspc_stack.get(), 0);
			const auto oidValue = sk_ASN1_TYPE_value(fmspc_stack.get(), 1);
			const auto oidValueLen = oidValue->value.octet_string->length;
			auto bytes = std::vector<uint8_t>(static_cast<size_t>(oidValueLen));
			std::copy_n(oidValue->value.octet_string->data, oidValueLen, bytes.begin());
			std::stringstream ss;
			for (int p : bytes)
			{
				ss << std::hex << p;
			}
			fmspc = ss.str();
			k_debug_msg("fmspc: %s", fmspc.c_str());
		}
	}
	if (fmspc.size() != 12)
	{
		 fmspc = fmspc+"00";
	}
	fmspcVal = fmspc;
}

void getIntermediateCrlUrl(X509* certX509, string& url)
{
	int nid1 = NID_crl_distribution_points;
	STACK_OF(DIST_POINT) * dist_points =(STACK_OF(DIST_POINT) *)X509_get_ext_d2i(certX509, nid1, NULL, NULL);
	DIST_POINT *dp = sk_DIST_POINT_value(dist_points, 0);
	DIST_POINT_NAME *distpoint = dp->distpoint;
	GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->name.fullname, 0);
	ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;
	url = string((char*)ASN1_STRING_data(asn1_str), ASN1_STRING_length(asn1_str));
	CRL_DIST_POINTS_free(dist_points);
}

void readQeIdentityFile(const char* path, std::string& qeIdenetity) {
	k_debug_msg("path to fetch file: %s", path);
	std::ifstream file(path, std::ios::in);
	if (!file.is_open())
	{
		k_info_msg("FAILED : failed to read the file!!!!!");
		return;
	}
	std::stringstream content;
	content << file.rdbuf();
	qeIdenetity = content.str();
	file.close();
}

gboolean verifyEcdsaQuote(k_buffer_ptr quote, u_int32_t public_key_size, u_int32_t totalSize, GString* tcbIfo_url,const char* qeIdentityPath)
{
	k_debug_msg("verifying ECDSA quote");
	gboolean ret = false;
	struct keyagent_sgx_quote_info *quote_info = (struct keyagent_sgx_quote_info *)k_buffer_data(quote);
	u_int32_t pckCert_size = (quote_info)->quote_details.ecdsa_quote_details.pckCert_size;
	u_int32_t quoteSize = (quote_info)->quote_size;
	k_buffer_ptr pckCert = NULL;
	k_buffer_ptr intermediateCrl = NULL;
	k_buffer_ptr tcbInfo = NULL;
	BIO* certBio = NULL;
	X509* certX509 = NULL;
	string intermediateCrlUrl, fmspcVal, qeIdentity;
	Status statusCode;
	size_t certLen = 0;
	const char* pckCertificate = NULL;

	pckCert = k_buffer_alloc(NULL, pckCert_size);

	if(!pckCert)
		return ret;
	
	memcpy(k_buffer_data(pckCert), (char *)(k_buffer_data(quote) + sizeof(struct keyagent_sgx_quote_info)), pckCert_size);
	((char *)k_buffer_data(pckCert))[pckCert_size]=0; ///This is necessary else junk value will come.

	const auto sgxQuote  = (k_buffer_data(quote) + sizeof(struct keyagent_sgx_quote_info) + public_key_size + pckCert_size);
	 
	certLen = k_buffer_length(pckCert);
	pckCertificate = (const char*)(k_buffer_data(pckCert));
	certBio = BIO_new(BIO_s_mem());
	BIO_write(certBio, pckCertificate, certLen);
	certX509 = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
	if (!certX509) {
		k_info_msg("unable to parse certificate in memory");
		goto out;
	}
	
	getIntermediateCrlUrl(certX509, intermediateCrlUrl);
	if (!intermediateCrlUrl.empty() ) {
		intermediateCrl = k_buffer_alloc(NULL,0);
		if (!fetchIntermediateCRL(intermediateCrlUrl.c_str(), intermediateCrl)) {
			k_info_msg("failed to get intermediateCrl");
			goto out;
		}
	} else {
		k_info_msg("failed to get intermediateCrlUrl");
		goto out;
	}

	getFMSPC(certX509, fmspcVal);
	if (!fmspcVal.empty()) {
        tcbInfo = k_buffer_alloc(NULL,0);
		if (!fetchTCBInfo(tcbIfo_url, fmspcVal.c_str(), tcbInfo)) {
				k_info_msg("failed to recieve TCBInfo");
				goto out;
		}
	} else {
			k_info_msg("failed to get fmspc");
			goto out;
	}
	if (qeIdentityPath != NULL) {
		readQeIdentityFile(qeIdentityPath, qeIdentity);
		if (qeIdentity.empty()) {
			k_info_msg("QeIdentity  file is not present/can't be read in the path: %s", qeIdentityPath);
			goto out;
		}
		statusCode = sgxAttestationVerifyQuote(sgxQuote, quoteSize-public_key_size, (const char*)(k_buffer_data(pckCert)), (const char*)(k_buffer_data(intermediateCrl)), (char *)(k_buffer_data(tcbInfo)), qeIdentity.c_str()); 
	} else {
		statusCode = sgxAttestationVerifyQuote(sgxQuote, quoteSize-public_key_size, (const char*)(k_buffer_data(pckCert)), (const char*)(k_buffer_data(intermediateCrl)), (char *)(k_buffer_data(tcbInfo)), NULL);
	}

	if (!statusCode) {
			k_info_msg("successfully verified ECDSA quote from DCAP library!!!!%d", statusCode);
			ret = true;
	} else {
			k_info_msg("ECDSA quote verification from DCAP library unsuccessful!!!!%d", statusCode);
	}
	
out:
	if (pckCert) k_buffer_unref(pckCert);
	if (certBio) BIO_free_all(certBio);
	return ret;
}
