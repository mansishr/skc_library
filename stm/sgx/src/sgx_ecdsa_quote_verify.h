#ifndef __SGX_ECDSA_QUOTE_VERIFY_H__
#define __SGX_ECDSA_QUOTE_VERIFY_H__

#include <glib.h>
#include <glib/gi18n.h>
#include <errno.h>
#include <iostream>
#include <memory>
#include "internal.h"
#include "include/k_debug.h"
#include <stdio.h>

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

DLL_LOCAL
gboolean fetchTCBInfo(const char* fmspc, k_buffer_ptr& return_data);

DLL_LOCAL
gboolean fetchIntermediateCRL(const char* abcd, k_buffer_ptr& return_data);

DLL_LOCAL
gboolean verifyEcdsaQuote(k_buffer_ptr quote, u_int32_t public_key_size, u_int32_t totalSize, GString* tcbIfo_url, const char* qeIdentity);

#endif //__SGX_ECDSA_QUOTE_VERIFY_H__
