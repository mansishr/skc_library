#define G_LOG_DOMAIN "util-curl"

#include "utils.h"

size_t DLL_LOCAL
__write_byte_array(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	k_buffer_ptr mem = (k_buffer_ptr )userp;
	k_buffer_append(mem, (guint8*) contents, realsize);
  	return realsize;
}

size_t DLL_LOCAL
__get_response_header(void *header_buffer, size_t size, size_t nmemb, void *userp)
{
	size_t realsize	= size * nmemb;
	GPtrArray *res_headers = (GPtrArray *)userp;
	gchar *header_element = g_strdup((const gchar *)header_buffer);
	g_ptr_array_add(res_headers, (gpointer) header_element);
	return realsize;
}

#define SETOPT(C,OPT,VAL) do { \
        if(curl_easy_setopt((C), (OPT), (VAL)) != CURLE_OK) { \
		g_critical("can't set  %s", #OPT); \
		return -1; \
        } \
}while(0)

void DLL_LOCAL
__build_header_list(gpointer data, gpointer user_data)
{
        struct curl_slist **header_list = (struct curl_slist **)user_data;
	gchar *s = (gchar *)data;
        *header_list = curl_slist_append(*header_list, s);
}

extern "C"
int 
skc_https_send(GString *url, GPtrArray *headers, GString *postdata, GPtrArray *response_headers, k_buffer_ptr returndata, keyagent_ssl_opts *ssl_opts, GString *userpwd, gboolean verbose)
{
	CURL *curl;
	struct curl_slist *header_list = NULL;
	long res_status = -1;
	gint verify = 0;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();
	if(!curl)
	{
		g_critical("curl_easy_init failed!");
		return -1;
	}

	SETOPT(curl, CURLOPT_URL, url->str);
	if(verbose)
		SETOPT(curl, CURLOPT_VERBOSE, 1L);

	if(ssl_opts) {
		if(ssl_opts->ssl_version)SETOPT(curl, CURLOPT_SSLVERSION, ssl_opts->ssl_version);
		if(ssl_opts->certtype)SETOPT(curl, CURLOPT_SSLCERTTYPE, ssl_opts->certtype);
		if(ssl_opts->certfile)SETOPT(curl, CURLOPT_SSLCERT, ssl_opts->certfile);
		if(ssl_opts->keytype)SETOPT(curl, CURLOPT_SSLKEYTYPE, ssl_opts->keytype);
		if(ssl_opts->keyname)SETOPT(curl, CURLOPT_SSLKEY, ssl_opts->keyname);
		if(ssl_opts->ca_certfile)SETOPT(curl, CURLOPT_CAINFO, ssl_opts->ca_certfile);
		if(ssl_opts->key_password)SETOPT(curl, CURLOPT_KEYPASSWD, ssl_opts->key_password);

		if(g_strcmp0(ssl_opts->keytype, FORMAT_ENG) == 0)
		{
			SETOPT(curl, CURLOPT_SSLENGINE, "pkcs11");
			SETOPT(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);
		}

		verify = (ssl_opts->ssl_verify == TRUE) ? 1 : 0;
		SETOPT(curl, CURLOPT_SSL_VERIFYPEER, verify);
	}
		
	if(postdata)
		SETOPT(curl, CURLOPT_POSTFIELDS, postdata->str);

	g_ptr_array_foreach(headers, __build_header_list, &header_list);

	SETOPT(curl, CURLOPT_HTTPHEADER, header_list);
	SETOPT(curl, CURLOPT_WRITEFUNCTION, __write_byte_array);
	SETOPT(curl, CURLOPT_WRITEDATA, returndata);

	if(userpwd)
	{
		SETOPT(curl, CURLOPT_USERPWD, userpwd->str);
		SETOPT(curl, CURLOPT_SSL_VERIFYPEER, verify);
	}
	if(response_headers)
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
