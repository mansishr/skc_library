#include <iostream>
#include <memory>
#include <time.h>
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <restbed>
#include <json/json.h>
#include <glib.h>
#include <glib/gi18n.h>
#include "keyserver.h"
#include "k_errors.h"
#include "key-agent/types.h"
#include "key-agent/key_agent.h"

using namespace std;
using namespace restbed;
using namespace server;

#define DT_FORMAT "%Y-%m-%dT%H:%M:%SZ"

void get_kms_key_usagepolices_method_handler( const shared_ptr< Session > session )
{
	const auto request = session->get_request();
	size_t content_length = request->get_header("Content-Length", 0);
	session->fetch(content_length, [request](const shared_ptr< Session > session, const Bytes & body)
	{
		const multimap< string, string > headers
		{
			{ "Content-Type", "application/json" }
		};
		int http_code = 200;
		Json::Value result;
		std::string out;

		GTimeVal ctime;
		g_get_current_time (&ctime);

		GDateTime *current_dt = g_date_time_new_from_timeval_local (&ctime);
		GDateTime *notafter_dt = g_date_time_add_months (current_dt, 1);

		k_debug_msg("current:%s, notafter:%s\n", g_date_time_format (current_dt, DT_FORMAT),
			g_date_time_format(notafter_dt,DT_FORMAT));

		result["status"]="success";
		result["operation"]="read key usage policy";
		result["data"]["id"] = "";
		result["data"]["not_after"] = g_date_time_format (notafter_dt, DT_FORMAT);
		result["data"]["not_before"] =  g_date_time_format (current_dt, DT_FORMAT);
		result["data"]["created_at"] = g_date_time_format (current_dt, DT_FORMAT);
		
	        out = json_to_string(result);
		session->close( http_code, out.c_str(), headers);
	});
}
