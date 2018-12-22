#ifndef __K_DEBUG_H__
#define __K_DEBUG_H__

#include "k_errors.h"
#include <glib.h>

#ifdef  __cplusplus

#include <iostream>
#include <sstream>

static inline gchar *
__k_debug_generate_checksum(gchar *data, int size)
{
    return g_compute_checksum_for_data (G_CHECKSUM_SHA256, (const guchar *)data, (gsize) size);
}

static inline void
k_debug_generate_checksum(const gchar *label, unsigned char *buf, unsigned int size)
{
    gchar *tmp =  __k_debug_generate_checksum((char *)buf, size);
    std::stringstream ss;
    ss << std::hex << tmp;
    std::string tmp1 = ss.str();
    k_debug_msg("%s %s\n", label, tmp1.c_str());
    g_free(tmp);
}

#else
static inline void
k_debug_generate_checksum(const gchar *label, unsigned char *buf, unsigned int size)
{
}

#endif

#endif
