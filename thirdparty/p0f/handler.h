#ifndef __HANDLER_H__
#define __HANDLER_H__

#include "config.h"

struct store_rec {
    u8 host[32];
    u8 os[32];
    u8 flavor[32];
};

// Detail of p0fhdlr struct will be put here
// to hide it from some module in Xplico
typedef struct _p0fhdlr {
    s32 link_type;
    s32 hash_seed;
    u32 tcp_sig_cnt[2][SIG_BUCKETS];
    u32 mtu_sig_cnt[SIG_BUCKETS];
/* Http Signatures aren't bucketed due to the complex matching used; but we use
   Bloom filters to go through them quickly. */
    u32 http_sig_cnt[2];
    struct tcp_sig_record *tcpsigs[2][SIG_BUCKETS];
    struct mtu_sig_record *mtusigs[SIG_BUCKETS];
    struct http_sig_record *httpsigs[2];
    
    /* http */
    u8** hdr_names;
    u32  hdr_cnt;                   /* Number of headers registered       */
    u32* hdr_by_hash[SIG_BUCKETS];  /* Hashed header names                */
    u32  hbh_cnt[SIG_BUCKETS];      /* Number of headers in bucket        */
    struct ua_map_record* ua_map;   /* Mappings between U-A and OS        */
    u32 ua_map_cnt;
    u32 class_cnt;                  /* Sizes for maps */
    u8** fp_os_classes;
    u32 name_cnt;
    u8** fp_os_names;

    CurlWrapper_t *es_conn_desc;
    u8 *es_buffer;
    u32 es_buffer_len;
    struct store_rec buff[ES_BUFF_SIZE];
    u32 buff_cnt;
} p0fhdlr;

#endif
