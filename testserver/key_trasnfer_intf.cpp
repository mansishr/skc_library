

#include <iostream>
#include <memory>

#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "keyserver.h"
#include <restbed>
#include <jsoncpp/json/json.h>
#include <glib.h>
#include <glib/gi18n.h>
#include "k_errors.h"
#include "key-agent/types.h"
#include "key-agent/key_agent.h"
#include "key-agent/src/internal.h"

using namespace std;
using namespace restbed;
using namespace server;


void keysession_authentication_handler( const shared_ptr< Session > session, const function< void ( const shared_ptr< Session > ) >& callback )
{
    auto authorisation = session->get_request( )->get_header( "Authorization" );
    callback( session );
}


char *
verify_challenge_and_encode_session(Json::Value &jsondata, challenge_info_t *info)
{
    keyagent_buffer_ptr quote = decode64_json_attr(jsondata, "quote");
    key_info_t *key_info = new key_info_t();
    key_info->swk = keyagent_stm_challenge_verify(server::stm, quote);
    g_hash_table_insert(server::key_hash_table,strdup(info->keyid.c_str()), key_info);
    char *encoded_swk = g_base64_encode(keyagent_buffer_data(key_info->swk), keyagent_buffer_length(key_info->swk));
    return encoded_swk;
}

void get_keysession_method_handler( const shared_ptr< Session > session )
{

    const auto request = session->get_request( );
    size_t content_length = request->get_header( "Content-Length", 0 );

    session->fetch( content_length, [ request ]( const shared_ptr< Session > session, const Bytes & body )
    {
        const multimap< string, string > headers
                {
                        { "Accept", "application/octet-stream"},
                        { "Content-Type", "application/json" }
                };
        int http_code = 200;

        k_debug_msg("%.*s", ( int ) body.size( ), body.data( ) );
        char *swk = NULL;
        std::unique_ptr<std::string> http_data = std::make_unique<std::string>(String::to_string(body));
        Json::Value jsondata = parse_data(http_data);
        std::string challenge = jsondata["challenge"].asString();
        Json::Value result;

        result["status"] = "Failed";

        challenge_info_t *info = (challenge_info_t *)g_hash_table_lookup (server::uuid_hash_table, challenge.c_str());
        if (!info)
        {
            k_critical_msg("invalid challenge %s", challenge.c_str());
            http_code = 401;
        } else
        {
            result["status"] = "ok";
            swk = verify_challenge_and_encode_session(jsondata, info);
            result["swk" ] = swk;
        }
        g_hash_table_remove(server::uuid_hash_table, challenge.c_str());
        std::string out = json_to_string(result);
        session->close( http_code, out.c_str(), headers);
        if (swk) g_free(swk);

    });
}

void keytransfer_authentication_handler( const shared_ptr< Session > session, const function< void ( const shared_ptr< Session > ) >& callback )
{
    auto authorisation = session->get_request( )->get_header( "Authorization" );
    callback( session );
}

Json::Value
get_challenge_info(std::string keyid, int *http_code)
{
    Json::Value val;
    *http_code = 401;
    try {
        Json::Value val1;
        Json::Value challenge_replyto;
        Json::Value link;
        val["status"] = "failure";
        val["operation"] = "key transfer";

        val1["type"] = "not-authorized";
        val["faults"] = val1;
        val["challenge"] = create_challenge(keyid);
        val["challenge_type"] = "SGX";
        challenge_replyto["href"] = "http://localhost:1984/keys/session";
        challenge_replyto["method"] = "post";

        link["challenge-replyto"] = challenge_replyto;
        val["link"] = link;


    } catch (...) {
        val["status"] = "failure";
    }
    return val;
}

Json::Value
get_key_info(key_info_t *key_info, int *http_code)
{
    Json::Value val;
    *http_code = 201;
    try {
        if (!key_info->key_attrs) {
            keyagent_key_attributes_ptr key_attrs = convert_key_to_attr_hash();
            keyagent_buffer_ptr IV = generate_iv();
            KEYAGENT_KEY_ADD_BYTEARRAY_ATTR(key_attrs, IV);
            key_info->key_attrs = keyagent_stm_wrap_key(server::stm, KEYAGENT_RSAKEY, key_attrs);
        }

        Json::Value json_data = keyattrs_to_json(key_info->key_attrs->hash);
        //std::cout << json_data.toStyledString() << std::endl;
        val["type"] = "RSA";
        for (auto const& id : json_data.getMemberNames())
            val[id] = json_data[id];

        val["status"] = "got-it";
    } catch (...) {
        val["status"] = "failure";
    }
    return val;
}

void get_keytransfer_method_handler( const shared_ptr< Session > session )
{
    const auto request = session->get_request( );
    size_t content_length = request->get_header( "Content-Length", 0 );

    session->fetch( content_length, [ request ]( const shared_ptr< Session > session, const Bytes & body )
    {

        Json::Value val;
        std::string keyid = request->get_header( "KeyId");
        key_info_t *key_info = (key_info_t *)g_hash_table_lookup(server::key_hash_table, keyid.c_str());

        print_input_headers("TRANSFER", session);
        const multimap< string, string > headers
                {
                        { "Content-Type", "application/json" }
                };

        int http_code = 2;
        std::unique_ptr<std::string> http_data = std::make_unique<std::string>(String::to_string(body));

        if (!key_info) {
            val = get_challenge_info(keyid, &http_code);
        } else {
            val = get_key_info(key_info, &http_code);
        }
        std::string out = json_to_string(val);
        session->close( http_code, out, headers);
    });
}
