#ifndef _CURL_H_
#define _CURL_H_

#ifdef  __cplusplus
extern "C" {
#endif

#include <curl/curl.h>
#include "k_types.h"

int skc_https_send(GString *url, GPtrArray *headers, GString *postdata, GPtrArray *response_headers, k_buffer_ptr returndata, keyagent_ssl_opts *ssl_opts, GString *userpwd, gboolean verbose);

#ifdef  __cplusplus
}
#endif

#endif
