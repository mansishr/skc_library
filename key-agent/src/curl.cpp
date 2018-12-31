#define G_LOG_DOMAIN "keyagent-curl"

#include <cstdint>
#include <curl/curl.h>
#include "key-agent/key_agent.h"
#include "key-agent/types.h"

size_t DLL_LOCAL
__write_byte_array(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	k_buffer_ptr mem = (k_buffer_ptr )userp;
	k_buffer_append (mem, (guint8*) contents, realsize);
  	return realsize;
}


size_t DLL_LOCAL
__get_response_header(void *header_buffer,   size_t size,   size_t nmemb,   void *userp)
{
	size_t realsize				= size * nmemb;
	GPtrArray *res_headers		= ( GPtrArray *)userp;
	gchar *header_element		= g_strdup ((const gchar *)header_buffer);
	g_ptr_array_add(res_headers, (gpointer) header_element);
	return realsize;
}

#define SETOPT(C,OPT,VAL) do { \
        if (curl_easy_setopt((C), (OPT), (VAL)) != CURLE_OK) { \
			g_error("can't set  %s", #OPT); \
        } \
} while (0)

void DLL_LOCAL
__build_header_list(gpointer data, gpointer user_data)
{
        struct curl_slist **header_list = (struct curl_slist **)user_data;
		gchar *s = (gchar *)data;
        *header_list = curl_slist_append(*header_list, s);
}

extern "C"
int DLL_LOCAL
__keyagent_https_send(GString *url, GPtrArray *headers, GString *postdata, GPtrArray *response_headers, k_buffer_ptr returndata, keyagent_ssl_opts *ssl_opts, gboolean verbose)
{
    CURL *curl;
    struct curl_slist *header_list = NULL;
    const char **cpp;
    long res_status = -1;

	curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl)
		g_error("curl_easy_init failed!");

    SETOPT(curl, CURLOPT_URL, url->str);
	if (verbose)
		SETOPT(curl, CURLOPT_VERBOSE, 1L);

	if (ssl_opts) {
    	if (ssl_opts->certtype) SETOPT(curl, CURLOPT_SSLCERTTYPE, ssl_opts->certtype);
    	if (ssl_opts->certfile) SETOPT(curl, CURLOPT_SSLCERT, ssl_opts->certfile);
    	if (ssl_opts->keytype) SETOPT(curl, CURLOPT_SSLKEYTYPE, ssl_opts->keytype);
    	if (ssl_opts->keyname) SETOPT(curl, CURLOPT_SSLKEY, ssl_opts->keyname);
    	if (ssl_opts->ca_certfile) SETOPT(curl, CURLOPT_CAINFO, ssl_opts->ca_certfile);
    	SETOPT(curl, CURLOPT_SSL_VERIFYPEER, 1);
	}
	if (postdata) 
		SETOPT(curl, CURLOPT_POSTFIELDS, postdata->str);

	g_ptr_array_foreach (headers, __build_header_list, &header_list);

    SETOPT(curl, CURLOPT_HTTPHEADER, header_list);
    SETOPT(curl, CURLOPT_WRITEFUNCTION, __write_byte_array);
    SETOPT(curl, CURLOPT_WRITEDATA, returndata);
	if ( response_headers )
	{
		SETOPT(curl, CURLOPT_HEADERFUNCTION, __get_response_header);
		SETOPT(curl, CURLOPT_HEADERDATA, response_headers);
	}


	curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res_status);
    curl_easy_cleanup(curl);

out:
	return res_status;
}
