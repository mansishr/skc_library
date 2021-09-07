#ifndef __K_ERRORS__
#define __K_ERRORS__

#define K_LOG_LEVEL_FATAL G_LOG_LEVEL_ERROR
#define K_LOG_LEVEL_WARN G_LOG_LEVEL_CRITICAL
#define K_LOG_LEVEL_INFO G_LOG_LEVEL_INFO
#define K_LOG_LEVEL_DEBUG G_LOG_LEVEL_DEBUG

#define K_LOG_DOMAIN_ERROR g_quark_from_static_string(G_LOG_DOMAIN)

#define k_set_domain_error(errptr, domain, code, args...) do { \
	g_clear_error(errptr); \
	g_set_error(errptr, domain, code, args); \
}while(0)

#define k_set_error(errptr, code, args...) do { \
	k_set_domain_error(errptr, K_LOG_DOMAIN_ERROR, code, args); \
}while(0)

#define k_domain_log(domain, level, args...) do { \
	g_log_structured(domain, level, "MESSAGE", args); \
}while(0)

#define  k_log(level, args...) do { \
	k_domain_log(G_LOG_DOMAIN, level, args); \
}while(0)

#define k_critical_msg(fmt...) do {\
	k_log(K_LOG_LEVEL_WARN, fmt); \
}while(0)

#define k_critical_error(err) do {\
	k_critical_msg("%s(%d): %s: (%s,%d)", \
	__FILE__, __LINE__, \
	(err)->message, g_quark_to_string((err)->domain), (err)->code); \
}while(0);

#define k_fatal_msg(fmt...) do {\
	k_log(K_LOG_LEVEL_FATAL, fmt); \
}while(0)

#define k_fatal_error(err) do {\
	k_fatal_msg("%s(%d): %s: (%s,%d)", \
	__FILE__, __LINE__, \
	(err)->message, g_quark_to_string((err)->domain), (err)->code); \
}while(0);

#define k_info_msg(fmt...) do {\
	k_log(K_LOG_LEVEL_INFO, fmt); \
}while(0)

#define k_info_error(err) do {\
	k_info_msg("%s(%d): %s: (%s,%d)", \
	__FILE__, __LINE__, \
	(err)->message, g_quark_to_string((err)->domain), (err)->code); \
}while(0);

#define k_debug_msg(fmt...) do {\
	k_log(K_LOG_LEVEL_DEBUG, fmt); \
}while(0)

#define k_debug_error(err) do {\
	k_debug_msg("%s(%d): %s: (%s,%d)", \
	__FILE__, __LINE__, \
	(err)->message, g_quark_to_string((err)->domain), (err)->code); \
}while(0);

#endif
