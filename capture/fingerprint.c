#include <stdio.h>
#include <stdlib.h>
#include <linux/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <glib.h>
#include "moloch.h"
#include "types.h"
#include "tcp.h"
#include "languages.h"
#include "picohttpparser.h"

#define MAX_SAVE_HOST       1
#define NAME_CHARS " ./-_!?()"
#define ROL32(_x, _r) (((_x) << (_r)) | ((_x) >> (32 - (_r))))
#define SLOF(_str) (u8*)_str, strlen((char*)_str)
#define LANG_HASH(_b0, _b1) (((_b0) * (_b1) ^ (_b1)) & 0xff)

#define SPECIAL_MSS         1331
#define SPECIAL_WIN         1337

#define SIG_BUCKETS         64
#define HOST_BUCKETS        1024

#ifndef MAX_SIT
#   define MAX_DIST         35
#endif
#define MAX_HOSTS           10000
#define HTTP_MAX_HDRS       32

#define MAX_TCP_OPT         24

/* IP-level quirks */
#define QUIRK_ECN           0x00000001  /* ECN supported */
#define QUIRK_DF            0x00000002  /* DF used (probably PMTUD) */
#define QUIRK_NZ_ID         0x00000004  /* Non-zero IDS when DF set */
#define QUIRK_ZERO_ID       0x00000008  /* Zero IDs when DF not set */
#define QUIRK_NZ_MBZ        0x00000010  /* IP "must be zero" field */
#define QUIRK_FLOW          0x00000020  /* IPv6 flows used */

/* TCP option quirks */
#define QUIRK_OPT_ZERO_TS1  0x01000000  /* Own timestamp set to zero */
#define QUIRK_OPT_NZ_TS2    0x02000000  /* Peer timestamp non-zero on SYN */
#define QUIRK_OPT_EOF_NZ    0x04000000  /* non-zero padding past EOL */
#define QUIRK_OPT_EXWS      0x08000000  /* Excessive window scaling */
#define QUIRK_OPT_BAD       0x10000000  /* Problem parsing TCP options */
#define QUIRK_ZERO_SEQ       0x00001000 /* SEQ is zero                        */
#define QUIRK_NZ_ACK         0x00002000 /* ACK non-zero when ACK flag not set */
#define QUIRK_ZERO_ACK       0x00004000 /* ACK is zero when ACK flag set      */
#define QUIRK_NZ_URG         0x00008000 /* URG non-zero when URG flag not set */
#define QUIRK_URG            0x00010000 /* URG flag set                       */
#define QUIRK_PUSH           0x00020000 /* PUSH flag on a control packet      */

/* TCP option quirks: */

#define QUIRK_OPT_ZERO_TS1   0x01000000 /* Own timestamp set to zero          */
#define QUIRK_OPT_NZ_TS2     0x02000000 /* Peer timestamp non-zero on SYN     */
#define QUIRK_OPT_EOL_NZ     0x04000000 /* Non-zero padding past EOL          */
#define QUIRK_OPT_EXWS       0x08000000 /* Excessive window scaling           */
#define QUIRK_OPT_BAD        0x10000000 /* Problem parsing TCP options        */

/* Methods for matching window size in tcp_sig: */

#define WIN_TYPE_NORMAL      0x00       /* Literal value                      */
#define WIN_TYPE_ANY         0x01       /* Wildcard (p0f.fp sigs only)        */
#define WIN_TYPE_MOD         0x02       /* Modulo check (p0f.fp sigs only)    */
#define WIN_TYPE_MSS         0x03       /* Window size MSS multiplier         */
#define WIN_TYPE_MTU         0x04       /* Window size MTU multiplier         */

/* List of fingerprinting modules: */

#define CF_MOD_TCP           0x00       /* fp_tcp.c                           */
#define CF_MOD_MTU           0x01       /* fp_mtu.c                           */
#define CF_MOD_HTTP          0x02       /* fp_http.c                          */

/* Parser states: */

#define CF_NEED_SECT         0x00       /* Waiting for [...] or 'classes'     */
#define CF_NEED_LABEL        0x01       /* Waiting for 'label'                */
#define CF_NEED_SYS          0x02       /* Waiting for 'sys'                  */
#define CF_NEED_SIG          0x03       /* Waiting for signatures, if any.    */
/* Flag to distinguish OS class and name IDs */

#define SYS_CLASS_FLAG       (1<<31)
#define SYS_NF(_x)           ((_x) & ~SYS_CLASS_FLAG)

#define FP_TYPE_NONE        0
#define FP_TYPE_OS          1
#define FP_TYPE_APP         2
#define FP_TYPE_LINK        3

struct fp_data {
    u8 ip_ver;                          /* IP_VER4, IP_VER6 */
    u8 tcp_type;                        /* TCP_SYN, ACK, FIN, RST */
    u8 src[16];                       /* Soure address(left-aligned) */
    u8 dst[16];                       /* Destination address (left-aligned) */
    u16 sport;                          /* Source port */
    u16 dport;                          /* Destination port */
    u8 ttl;                             /* Observed TTL */
    u8 tos;                             /* IP ToS value */
    u16 mss;                            /* Maximum segment size */
    u16 win;                            /* Window size */
    u8 wscale;                          /* Window scaling */
    u16 tot_hdr;                        /* Total headers (for MTU calc) */
    u8 opt_layout[MAX_TCP_OPT];         /* Ordering of TCP options */
    u8 opt_cnt;                         /* Count of TCP options */
    u8 opt_eol_pad;                     /* Amount of padding past EOL */
    u32 ts1;                            /* Own timestamp */
    u32 quirks;                         /* QUIRK */
    u8 ip_opt_len;                      /* Length of IP options */
    u8 *payload;                        /*  TCP payload */
    u16 pay_len;                        /* Length of TCP payload */
    u32 seq;                            /* seq value seen */
};

/* Simplified data for signature matching and NAT detection: */

struct tcp_sig {

  u32 opt_hash;                         /* Hash of opt_layout & opt_cnt       */
  u32 quirks;                           /* Quirks                             */

  u8  opt_eol_pad;                      /* Amount of padding past EOL         */
  u8  ip_opt_len;                       /* Length of IP options               */

  s8  ip_ver;                           /* -1 = any, IP_VER4, IP_VER6         */

  u8  ttl;                              /* Actual TTL                         */

  s32 mss;                              /* Maximum segment size (-1 = any)    */
  u16 win;                              /* Window size                        */
  u8  win_type;                         /* WIN_TYPE_*                         */
  s16 wscale;                           /* Window scale (-1 = any)            */

  s8  pay_class;                        /* -1 = any, 0 = zero, 1 = non-zero   */

  u16 tot_hdr;                          /* Total header length                */
  u32 ts1;                              /* Own timestamp                      */
  u64 recv_ms;                          /* Packet recv unix time (ms)         */

  /* Information used for matching with p0f.fp: */

  struct tcp_sig_record* matched;       /* NULL = no match                    */
  u8  fuzzy;                            /* Approximate match?                 */
  u8  dist;                             /* Distance                           */

};

struct tcp_sig_record {

  u8  generic;                          /* Generic entry?                     */
  s32 class_id;                         /* OS class ID (-1 = user)            */
  s32 name_id;                          /* OS name ID                         */
  u8* flavor;                           /* Human-readable flavor string       */

  u32 label_id;                         /* Signature label ID                 */

  u32* sys;                             /* OS class / name IDs for user apps  */
  u32  sys_cnt;                         /* Length of sys                      */

  u32  line_no;                         /* Line number in p0f.fp              */

  u8  bad_ttl;                          /* TTL is generated randomly          */

  struct tcp_sig* sig;                  /* Actual signature data              */

};

/* HTTP header field: */

struct http_hdr {
    s32  id;                              /* Lookup ID (-1 = none)              */
    u8*  name;                            /* Text name (NULL = use lookup ID)   */
    u8*  value;                           /* Value, if any                      */
    u8   optional;                        /* Optional header?                   */
};

/* Request / response signature collected from the wire: */
struct http_sig {
    s8  http_ver;                         /* HTTP version (-1 = any)            */
    struct http_hdr hdr[HTTP_MAX_HDRS];   /* Mandatory / discovered headers     */
    u32 hdr_cnt;

    u64 hdr_bloom4;                       /* Bloom filter for headers           */

    u32 miss[HTTP_MAX_HDRS];              /* Missing headers                    */
    u32 miss_cnt;

    u8* sw;                               /* Software string (U-A or Server)    */
    u8* lang;                             /* Accept-Language                    */
    u8* via;                              /* Via or X-Forwarded-For             */

    u32 date;                             /* Parsed 'Date'                      */
    u32 recv_date;                        /* Actual receipt date                */

    /* Information used for matching with p0f.fp: */
    struct http_sig_record* matched;      /* NULL = no match                    */
    u8  dishonest;                        /* "sw" looks forged?                 */
};

/* Record for a HTTP signature read from p0f.fp: */

struct http_sig_record {
    s32 class_id;                         /* OS class ID (-1 = user)            */
    s32 name_id;                          /* OS name ID                         */
    u8* flavor;                           /* Human-readable flavor string       */
    u32 label_id;                         /* Signature label ID                 */
    u32* sys;                             /* OS class / name IDs for user apps  */
    u32  sys_cnt;                         /* Length of sys                      */
    u32  line_no;                         /* Line number in p0f.fp              */
    u8 generic;                           /* Generic signature?                 */
    struct http_sig* sig;                 /* Actual signature data              */
};

/* Record for a TCP signature read from p0f.fp */
struct mtu_sig_record {
    u8 *name;
    u16 mtu;
};

/* Another internal structure for UA -> OS maps: */
struct ua_map_record {
    char *name;
    u32 id;
};

/* A structure used for looking up various headers internally in fp_http.c: */
struct http_id {
    char* name;
    u32 id;
};

struct config_status {
    u32 line_no;
    u32 class_cnt;
    u32 name_cnt;
    u32 label_id;
    s32 sig_class;
    u32 sig_name;
    u8 *sig_flavor;
    u32* cur_sys;
    u32 cur_sys_cnt;
    u32 sig_cnt;
    u8  state;
    u8 mod_type;
    u8 mod_to_srv;
    u8 generic;
};

static void packet_to_fpdata(MolochPacket_t * const packet, struct fp_data *fpdata);
static void fpdata_to_sig(struct fp_data *fpdata, struct tcp_sig *sig);
static void gen_hash_seed(void);
static void tcp_find_match(u8 to_srv, struct tcp_sig* ts, u8 dupe_det, u16 syn_mss);
static struct tcp_sig *process_tcp(u8 to_srv, struct fp_data *fpdata, MolochFpFlow_t *f);
static void process_mtu(u8 to_srv, struct fp_data *fpdata, MolochFpFlow_t *f);
static inline u32 hash32(const void* key, u32 len, u32 seed);
static s16 detect_win_multi(struct tcp_sig* ts, u8* use_mtu, u16 syn_mss);
static u8 guess_dist(u8 ttl);
static MolochFpFlow_t *init_flow();
static void read_config(const char *fname);
static void config_parse_line(u8* line);
static void config_parse_classes(u8* val);
void http_parse_ua(u8* val, u32 line_no);
u32 lookup_name_id(char* name, u8 len);
static void config_parse_label(char* val);
static void config_parse_sys(u8* val);
void mtu_register_sig(u8* name, u8* val, u32 line_no);
void tcp_register_sig(u8 to_srv, u8 generic, s32 sig_class, u32 sig_name,
                      u8* sig_flavor, u32 label_id, u32* sys, u32 sys_cnt,
                      u8* val, u32 line_no);
void http_register_sig(u8 to_srv, u8 generic, s32 sig_class, u32 sig_name,
                       u8* sig_flavor, u32 label_id, u32* sys, u32 sys_cnt,
                       u8* val, u32 line_no);
static void save_fp_result(MolochFpHost_t *host);
MolochFpHost_t *lookup_host(char* addr, u8 ip_ver);
static u32 get_host_bucket(char* addr, u8 ip_ver);
static int update_host_change(MolochFpHost_t *old_host, MolochFpHost_t *new_host);
static void insert_host(MolochFpHost_t *new_host);
static void touch_host(MolochFpHost_t *host);
static void nuke_hosts(void);
static void remove_host(MolochFpHost_t *host);
static s32 lookup_hdr(u8* name, u32 len, u8 create);
static inline u64 bloom4_64(u32 val);
static void http_find_match(u8 to_srv, struct http_sig* ts, u8 dupe_det);
static void http_init(void);
static u32 parse_date(u8* str);
static void process_http(u8 to_srv, MolochFpFlow_t *f);
void free_sig_hdrs(struct http_sig* h);

/* Headers that should be tagged as optional by the HTTP fingerprinter in any
   generated signatures: */
static struct http_id req_optional[] = {
    { "Cookie", 0 }, 
    { "Referer", 0 },
    { "Origin", 0 },
    { "Range", 0 },
    { "If-Modified-Since", 0 },
    { "If-None-Match", 0 },
    { "Via", 0 },
    { "X-Forwarded-For", 0 },
    { "Authorization", 0 },
    { "Proxy-Authorization", 0 },
    { "Cache-Control", 0 },
    { 0, 0 }
};

static struct http_id resp_optional[] = {
    { "Set-Cookie", 0 },
    { "Last-Modified", 0 },
    { "ETag", 0 },
    { "Content-Length", 0 },
    { "Content-Disposition", 0 },
    { "Cache-Control", 0 },
    { "Expires", 0 },
    { "Pragma", 0 },
    { "Location", 0 },
    { "Refresh", 0 },
    { "Content-Range", 0 },
    { "Vary", 0 },
    { 0, 0 }
};

/* Common headers that are expected to be present at all times, and deserve
   a special mention if absent in a signature: */
static struct http_id req_common[] = {
    { "Host", 0 },
    { "User-Agent", 0 },
    { "Connection", 0 },
    { "Accept", 0 },
    { "Accept-Encoding", 0 },
    { "Accept-Language", 0 },
    { "Accept-Charset", 0 },
    { "Keep-Alive", 0 },
    { 0, 0 }
};

static struct http_id resp_common[] = {
    { "Content-Type", 0 },
    { "Connection", 0 },
    { "Keep-Alive", 0 },
    { "Accept-Ranges", 0 },
    { "Date", 0 },
    { 0, 0 }
};

/* Headers for which values change depending on the context, and therefore
   should not be included in proposed signatures. This is on top of the
   "optional" header lists, which already implies skipping the value. */
static struct http_id req_skipval[] = {
    { "Host", 0 },
    { "User-Agent", 0 },
    { 0, 0 }
};

static struct http_id resp_skipval[] = {
    { "Date", 0 },
    { "Content-Type", 0 },
    { "Server", 0 },
    { 0, 0 }
};


extern MolochConfig_t   config;
static u32 hash_seed;
static struct tcp_sig_record *tcp_sigs[2][SIG_BUCKETS];
static u32 tcp_sig_cnt[2][SIG_BUCKETS];
/* Signatures aren't bucket due to the complex matching used; but we use Bloom Filters to go through them quickly */
static struct http_sig_record *http_sigs[2];
static u32 http_sig_cnt[2];
static char **fp_os_classes, **fp_os_names;
static u32 ua_map_cnt;
static struct ua_map_record *ua_map;
static u32 host_cnt;

static struct config_status conf;
static MolochFpHost_t *host_b[HOST_BUCKETS];
static MolochFpHost_t *host_by_age;
static MolochFpHost_t *newest_host;

static u8 **hdr_names;                      /* List of header names by ID */
static u32 hdr_cnt;                         /* Number of headers registered */

static u32 *hdr_by_hash[SIG_BUCKETS];       /* Hashed header names */
static u32 hbh_cnt[SIG_BUCKETS];            /* Number of headers in bucket */

static struct mtu_sig_record *mtu_sigs[SIG_BUCKETS];
static u32 mtu_sig_cnt[SIG_BUCKETS];

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void fingerprint_init()
{
    gen_hash_seed();
    conf.state = CF_NEED_SECT;
    http_init();
    read_config("/home/meo/test/p0f.fp");
}

/* Pre-register essential headers. */
static void http_init(void) {
    u32 i;

    /* Do not change - other code depends on the ordering of first 6 entries. */
    lookup_hdr(SLOF("User-Agent"), 1);      /* 0 */
    lookup_hdr(SLOF("Server"), 1);          /* 1 */
    lookup_hdr(SLOF("Accept-Language"), 1); /* 2 */
    lookup_hdr(SLOF("Via"), 1);             /* 3 */
    lookup_hdr(SLOF("X-Forwarded-For"), 1); /* 4 */
    lookup_hdr(SLOF("Date"), 1);            /* 5 */
#define HDR_UA  0
#define HDR_SRV 1
#define HDR_AL  2
#define HDR_VIA 3
#define HDR_XFF 4
#define HDR_DAT 5
    i = 0;
    while (req_optional[i].name) {
        req_optional[i].id = lookup_hdr(SLOF(req_optional[i].name), 1);
        i++;
    }

    i = 0;
    while (resp_optional[i].name) {
      resp_optional[i].id = lookup_hdr(SLOF(resp_optional[i].name), 1);
      i++;
    }
    i = 0;
    while (req_skipval[i].name) {
      req_skipval[i].id = lookup_hdr(SLOF(req_skipval[i].name), 1);
      i++;
    }
    i = 0;
    while (resp_skipval[i].name) {
      resp_skipval[i].id = lookup_hdr(SLOF(resp_skipval[i].name), 1);
      i++;
    }
    i = 0;
    while (req_common[i].name) {
      req_common[i].id = lookup_hdr(SLOF(req_common[i].name), 1);
      i++;
    }
    i = 0;
    while (resp_common[i].name) {
      resp_common[i].id = lookup_hdr(SLOF(resp_common[i].name), 1);
      i++;
    }
}

void fingerprint_close()
{
    int i;
    MolochFpHost_t *p;
    for (i = 0; i < HOST_BUCKETS; i++) {
        while (host_b[i]) {
            p = host_b[i];
            host_b[i] = host_b[i]->next;
            free(p);
        }
    }
}

void fingerprint_tcp(MolochSession_t * const session, MolochPacket_t * const packet)
{
    struct fp_data fpdata;
    memset(&fpdata, 0, sizeof(struct fp_data));
    packet_to_fpdata(packet, &fpdata);
    struct tcp_sig *tsig;
    switch (fpdata.tcp_type) {
        case TCP_SYN:
            if (session->fflow) {
#ifdef TESTMODE
                LOG("[#] New SYN for and existing flow, resetting\n");
#endif
                fingerprint_destroy_flow(&session->fflow);
            }
            session->fflow = init_flow();
            session->fflow->client.thread = session->thread;
            session->fflow->client.times = session->lastPacket.tv_sec;
            strncpy(session->fflow->client.addr, fpdata.src, 16);
            session->fflow->client.ip_ver = fpdata.ip_ver;
            session->fflow->client.is_srv = 0;
            tsig = process_tcp(1, &fpdata, session->fflow);
            if (!tsig && !session->fflow->sendsyn) {
                fingerprint_destroy_flow(&session->fflow);
                return;
            }
            process_mtu(1, &fpdata, session->fflow);
            break;
        case TCP_SYN | TCP_ACK:
            if (!session->fflow) {
#ifdef TESTMODE
                LOG("[#] Stray SYN+ACK with no flow.\n");
#endif
                return;
            }
            session->fflow->server.times = session->lastPacket.tv_sec;
            session->fflow->server.ip_ver = fpdata.ip_ver;
            session->fflow->server.thread = session->thread;
            strncpy(session->fflow->server.addr, fpdata.src, 16);
            session->fflow->client.is_srv = 1;
            if (session->fflow->sendsyn) {
                process_tcp(0, &fpdata, session->fflow);
                fingerprint_destroy_flow(&session->fflow);
                return;
            }
            if (session->fflow->acked) {
                if (session->fflow->next_srv_seq - 1 != fpdata.seq)
#ifdef TESTMODE
                    LOG("[#] Repeated but non-identical SYN+ACK (0x%08x != 0x%08x).\n",
                                session->fflow->next_srv_seq - 1, fpdata.seq);
#endif
                return;
            }
            session->fflow->acked = 1;
            tsig = process_tcp(0, &fpdata, session->fflow);
            /* SYN from real OS, SYN+ACK from a client stack. Weird, but whatever. */
            if (!tsig) {
                fingerprint_destroy_flow(&session->fflow);
                return;
            }
            process_mtu(0, &fpdata, session->fflow);
            session->fflow->next_srv_seq = fpdata.seq + 1;
            break;
    }
}

void fingerprint_http(MolochSession_t * const session, struct phr_header *hdrs, uint32_t hdr_num, uint8_t to_srv, uint8_t http_ver)
{
    u32 hcount = 0;
    s32 hid;
    int i;
    MolochFpFlow_t *f = session->fflow;
    if (f->in_http < 0) return;
    if (to_srv && f->http_req_done) return;
    struct http_sig *http_tmp = (struct http_sig *)f->http_tmp;
    http_tmp->http_ver = http_ver;
    //Store the header name and value
    for (i = 0; i < hdr_num; i++) {
        hid = lookup_hdr(hdrs[i].name, hdrs[i].name_len, 0);
        http_tmp->hdr[hcount].id = hid;
        if (hid < 0) {
            /* Header ID not found, store literal value. */
            http_tmp->hdr[hcount].name = strdup(hdrs[i].name);
        }
        else {
            http_tmp->hdr_bloom4 |= bloom4_64(hid);
        }
        if (hdrs[i].value_len) {
            u8 *val = (u8 *)strndup(hdrs[i].value, hdrs[i].value_len);
            http_tmp->hdr[hcount].value = val;
            if (to_srv) {
                switch (hid) {
                    case HDR_UA:
                        http_tmp->sw = val;
                        break;
                    case HDR_AL:
                        http_tmp->lang = val;
                        break;
                    case HDR_VIA:
                    case HDR_XFF:
                        http_tmp->via = val;
                        break;
                }
            } else {
                switch (hid) {
                    case HDR_SRV:
                        http_tmp->sw = val;
                        break;
                    case HDR_DAT:
                        http_tmp->date = parse_date(val);
                        break;
                    case HDR_VIA:
                    case HDR_XFF:
                        http_tmp->via = val;
                        break;
                }
            }
        }
        hcount++;
    }
    http_tmp->hdr_cnt = hcount;
    process_http(to_srv, f);
    if (to_srv) {
        f->http_req_done = 1;
        free_sig_hdrs(http_tmp);
        memset(http_tmp, 0, sizeof(struct http_sig));
    }
    else {
        f->in_http = -1;
    }
}

static void packet_to_fpdata(MolochPacket_t * const packet, struct fp_data *fpdata)
{
    struct tcp_hdr *tcp;
    fpdata->quirks = 0;
    fpdata->ip_ver = *(packet->pkt + packet->ipOffset) >> 4;
    if (fpdata->ip_ver == IP_VER4) {
        const struct ipv4_hdr *ip4 = (struct ipv4_hdr *)(packet->pkt + packet->ipOffset);
        u32 hdr_len = packet->payloadOffset - packet->ipOffset;
        u16 flags_off = ntohs(RD16(ip4->flags_off));
        fpdata->ip_opt_len = hdr_len - 20;
        memcpy(fpdata->src, ip4->src, 4);
        memcpy(fpdata->dst, ip4->dst, 4);
        fpdata->tos = ip4->tos_ecn >> 2;
        fpdata->ttl = ip4->ttl;
        if (ip4->tos_ecn & (IP_TOS_CE | IP_TOS_ECT)) fpdata->quirks |= QUIRK_ECN;
        if (flags_off & IP4_MBZ) fpdata->quirks |= QUIRK_NZ_MBZ;
        if (flags_off & IP4_DF) {
            fpdata->quirks |= QUIRK_DF;
            if (RD16(ip4->id)) fpdata->quirks |= QUIRK_NZ_ID;
        }
        else {
            if (!RD16(ip4->id)) fpdata->quirks |= QUIRK_ZERO_ID;
        }
        fpdata->tot_hdr = hdr_len;
        tcp = (struct tcp_hdr *)(packet->pkt + packet->payloadOffset);
    }
    else if (fpdata->ip_ver == IP_VER6) {
        const struct ipv6_hdr *ip6 = (struct ipv6_hdr *)(packet->pkt + packet->ipOffset);
        u32 ver_tos = ntohl(RD32(ip6->ver_tos));
        fpdata->ip_opt_len = 0;
        memcpy(fpdata->src, ip6->src, 16);
        memcpy(fpdata->dst, ip6->dst, 16);
        fpdata->tos = (ver_tos >> 22) & 0x3F;
        fpdata->ttl = ip6->ttl;
        if (ver_tos && 0xFFFFF) fpdata->quirks |= QUIRK_FLOW;
        if ((ver_tos >> 20) & (IP_TOS_CE | IP_TOS_ECT)) fpdata->quirks |= QUIRK_ECN;
        fpdata->tot_hdr = sizeof(struct ipv6_hdr);
        tcp = (struct tcp_hdr *)(ip6 + 1);
    }
    else {
        return;
    }

    u32 tcp_doff = (tcp->doff_rsvd >> 4) * 4;
    fpdata->tot_hdr += tcp_doff;
    fpdata->sport = ntohs(RD16(tcp->sport));
    fpdata->dport = ntohs(RD16(tcp->dport));
    fpdata->tcp_type = tcp->flags & (TCP_SYN | TCP_ACK | TCP_FIN | TCP_RST);
    fpdata->win = ntohs(RD16(tcp->win));
    fpdata->seq = ntohs(RD32(tcp->seq));
    if ((tcp->flags & (TCP_ECE | TCP_CWR)) ||
            (tcp->doff_rsvd & TCP_NS_RES)) fpdata->quirks |= QUIRK_ECN;
    if (!fpdata->seq) fpdata->quirks |= QUIRK_ZERO_SEQ;
    if (tcp->flags & TCP_ACK) {
        if (!RD32(tcp->ack)) fpdata->quirks |= QUIRK_ZERO_ACK;
    }
    else {
        if (RD32(tcp->ack) & !(tcp->flags & TCP_RST)) {
            fpdata->quirks |= QUIRK_NZ_ACK;
        }
    }
    if (tcp->flags & TCP_URG) {
        fpdata->quirks |= QUIRK_URG;
    }
    else {
        if (RD16(tcp->urg)) {
            fpdata->quirks |= QUIRK_NZ_URG;
        }
    }
    if (tcp->flags & TCP_PUSH) fpdata->quirks |= QUIRK_PUSH;

    /* Handle payload data */
    if (tcp_doff == packet->pktlen) {
        fpdata->payload = NULL;
        fpdata->pay_len = 0;
    }
    else {
        fpdata->payload = packet->pkt + packet->payloadOffset + tcp_doff;
        fpdata->pay_len = packet->payloadLen - tcp_doff;
    }

    /* TCP option parsing */
    u8 *opt_end = packet->pkt + packet->payloadOffset + tcp_doff;   /* First byte of non-option data */
    u8 *data = (u8 *)(tcp + 1);
    fpdata->opt_cnt = 0;
    fpdata->opt_eol_pad = 0;
    fpdata->mss = 0;
    fpdata->wscale = 0;
    fpdata->ts1 = 0;

    while (data < opt_end && fpdata->opt_cnt < MAX_TCP_OPT) {
        fpdata->opt_layout[fpdata->opt_cnt++] = *data;
        switch (*data++) {
            case TCPOPT_EOL:
                /* EOF is a single-byte option that aborts further option parsing.
                   Take note of how many bytes of option data are left, and if any of them
                   are non-zero. */
                fpdata->opt_eol_pad = opt_end - data;
                while (data < opt_end && !*data++);
                if (data != opt_end) {
                    fpdata->quirks |= QUIRK_OPT_EOL_NZ;
                    data = opt_end;
                }
                break;
            case TCPOPT_NOP:
                /* NOP is a single-byte option that does nothing */
                break;
            case TCPOPT_MAXSEG:
                /* MSS is a four-byte option with specified size */
                if (*data != 4) {
                    fpdata->quirks |= QUIRK_OPT_BAD;
                }
                if (data + 3 > opt_end) {
                    goto abort_options;
                }
                fpdata->mss = ntohs(RD16p(data+1));
                data += 3;
                break;
            case TCPOPT_WSCALE:
                /* WS is a three-byte option with specified size */
                if (*data != 3) {
                    fpdata->quirks |= QUIRK_OPT_BAD;
                }
                if (data + 2 > opt_end) {
                    goto abort_options;
                }
                fpdata->wscale = data[1];
                if (fpdata->wscale > 14) fpdata->quirks |= QUIRK_OPT_EXWS;
                data += 2;
                break;
            case TCPOPT_SACKOK:
                /* SACKOK is a two byte option with specified size */
                if (*data != 2) {
                    fpdata->quirks |= QUIRK_OPT_BAD;
                }
                if (data + 1 > opt_end) {
                    goto abort_options;
                }
                data++;
                break;
            case TCPOPT_SACK:
                /* SACK is a variable-length option of 10 to 34 bytes. Because
                   we don't know the size any better, we need to bail out if it looks wonky */
                if (*data < 10 || *data > 34) {
                    goto abort_options;
                }
                if (data - 1 + *data > opt_end) {
                    goto abort_options;
                }
                data += *data - 1;
                break;
            case TCPOPT_TSTAMP:
                if (*data != 10) {
                    fpdata->quirks |= QUIRK_OPT_BAD;
                }
                if (data + 9 > opt_end) {
                    goto abort_options;
                }
                fpdata->ts1 = ntohl(RD32p(data + 1));
                if (!fpdata->ts1) fpdata->quirks |= QUIRK_OPT_ZERO_TS1;
                if (fpdata->tcp_type == TCP_SYN && RD32p(data + 5)) {
                    fpdata->quirks |= QUIRK_OPT_NZ_TS2;
                }
                data += 9;
                break;
            default:
                /* Unknown option, presumably with specified size */
                if (*data < 2 || *data > 40) {
                    goto abort_options;
                }
                if (data - 1 + *data > opt_end) {
                    goto abort_options;
                }
                data += *data - 1;
        }
    }
    if (data != opt_end) {
abort_options:
        fpdata->quirks |= QUIRK_OPT_BAD;
    }
}

static void fpdata_to_sig(struct fp_data *fpdata, struct tcp_sig *sig)
{
    sig->opt_hash       = hash32(fpdata->opt_layout, fpdata->opt_cnt, hash_seed);
    sig->quirks         = fpdata->quirks;
    sig->opt_eol_pad    = fpdata->opt_eol_pad;
    sig->ip_opt_len     = fpdata->ip_opt_len;
    sig->ip_ver         = fpdata->ip_ver;
    sig->ttl            = fpdata->ttl;
    sig->mss            = fpdata->mss;
    sig->win            = fpdata->win;
    sig->win_type       = WIN_TYPE_NORMAL;
    sig->wscale         = fpdata->wscale;
    sig->pay_class      = !!fpdata->pay_len;
    sig->tot_hdr        = fpdata->tot_hdr;
    sig->ts1            = fpdata->ts1;
    sig->matched        = NULL;
    sig->fuzzy          = 0;
    sig->dist           = 0;
}

static struct tcp_sig *process_tcp(u8 to_srv, struct fp_data *fpdata, MolochFpFlow_t *f) {
    struct tcp_sig *sig;
    struct tcp_sig_record *m;

    sig = calloc(sizeof(struct tcp_sig), 1);
    fpdata_to_sig(fpdata, sig);
    if (fpdata->tcp_type == TCP_SYN && fpdata->win == SPECIAL_WIN && fpdata->mss == SPECIAL_MSS)
        f->sendsyn = 1;
    tcp_find_match(to_srv, sig, 0, f->syn_mss);
    MolochFpHost_t *host = (to_srv ? &f->client : &f->server);
    if ((m = sig->matched)) {
        if (m->class_id == -1 || f->sendsyn) {
            sprintf(host->app, "%s%s%s", fp_os_names[m->name_id], m->flavor ? " " : "", m->flavor ? m->flavor : (u8*)"");
        }
        else {
            sprintf(host->os, "%s%s%s", fp_os_names[m->name_id], m->flavor ? " " : "", m->flavor ? m->flavor : (u8*)"");
        }
    }
    else {
        host->os[0] = '\0';
        host->app[0] = '\0';
    }
    if (fpdata->tcp_type == TCP_SYN) f->syn_mss = fpdata->mss;
    /* That's about as far as we go with non-OS signatures */
    if (m && m->class_id == -1) {
        //verify_tool_class(to_srv, f, m->sys, m->sys_cnt);
        free(sig);
        return NULL;
    }
    if (f->sendsyn) {
        free(sig);
        return NULL;
    }
    return sig;
}

static void process_mtu(u8 to_srv, struct fp_data *fpdata, MolochFpFlow_t *f)
{
    u32 bucket, i, mtu;

    if (!fpdata->mss || f->sendsyn) return;

    if (fpdata->ip_ver == IP_VER4) mtu = fpdata->mss + MIN_TCP4;
    else mtu = fpdata->mss + MIN_TCP6;

    bucket = (mtu) % SIG_BUCKETS;

    for (i = 0; i < mtu_sig_cnt[bucket]; i++)
        if (mtu_sigs[bucket][i].mtu == mtu) break;

    MolochFpHost_t *host = (to_srv ? &f->client : &f->server);
    if (i == mtu_sig_cnt[bucket]) {
        host->link[0] = '\0';
    }
    else {
        sprintf(host->link, "%s", mtu_sigs[bucket][i].name);
    }
}

static void gen_hash_seed(void)
{
    s32 f = open("/dev/urandom", O_RDONLY);
    if (f < 0) {
        LOG("Cannot open /dev/urandom for reading");
        return;
    }
    if (read(f, &hash_seed, sizeof(hash_seed)) != sizeof(hash_seed))
        LOG("Cannot read data from /dev/urandom\n");
    close(f);
}

static inline u32 hash32(const void* key, u32 len, u32 seed) {

  u32 a, b, c;
  const u8* k = key;

  a = b = c = 0xdeadbeef + len + seed;

  while (len > 12) {

    a += RD32p(k);
    b += RD32p(k + 4);
    c += RD32p(k + 8);

    a -= c; a ^= ROL32(c,  4); c += b;
    b -= a; b ^= ROL32(a,  6); a += c;
    c -= b; c ^= ROL32(b,  8); b += a;
    a -= c; a ^= ROL32(c, 16); c += b;
    b -= a; b ^= ROL32(a, 19); a += c;
    c -= b; c ^= ROL32(b,  4); b += a;

    len -= 12;
    k += 12;

  }

  switch (len) {

    case 12: c += RD32p(k + 8);
             b += RD32p(k+ 4);
             a += RD32p(k); break;

    case 11: c += (RD16p(k + 8) << 8) | k[10];
             b += RD32p(k + 4);
             a += RD32p(k); break;

    case 10: c += RD16p(k + 8);
             b += RD32p(k + 4);
             a += RD32p(k); break;

    case 9:  c += k[8];
             b += RD32p(k + 4);
             a += RD32p(k); break;

    case 8:  b += RD32p(k + 4);
             a += RD32p(k); break;

    case 7:  b += (RD16p(k + 4) << 8) | k[6] ;
             a += RD32p(k); break;

    case 6:  b += RD16p(k + 4);
             a += RD32p(k); break;

    case 5:  b += k[4];
             a += RD32p(k); break;

    case 4:  a += RD32p(k); break;

    case 3:  a += (RD16p(k) << 8) | k[2]; break;

    case 2:  a += RD16p(k); break;

    case 1:  a += k[0]; break;

    case 0:  return c;

  }

  c ^= b; c -= ROL32(b, 14);
  a ^= c; a -= ROL32(c, 11);
  b ^= a; b -= ROL32(a, 25);
  c ^= b; c -= ROL32(b, 16);
  a ^= c; a -= ROL32(c, 4);
  b ^= a; b -= ROL32(a, 14);
  c ^= b; c -= ROL32(b, 24);

  return c;

}

static void tcp_find_match(u8 to_srv, struct tcp_sig* ts, u8 dupe_det, u16 syn_mss)
{
    struct tcp_sig_record *fmatch = NULL;
    struct tcp_sig_record *gmatch = NULL;

    u32 bucket = ts->opt_hash % SIG_BUCKETS;
    u32 i;

    u8 use_mtu = 0;
    s16 win_multi = detect_win_multi(ts, &use_mtu, syn_mss);
    for (i = 0; i < tcp_sig_cnt[to_srv][bucket]; i++) {
        struct tcp_sig_record* ref = tcp_sigs[to_srv][bucket] + i;
        struct tcp_sig* refs = ref->sig;

        u8 fuzzy = 0;
        u32 ref_quirks = refs->quirks;

        if (ref->sig->opt_hash != ts->opt_hash) continue;

        /* If the p0f.fp signature has no IP version specified, we need
           to remove IPv6-specific quirks from it when matching IPv4
           packets, and vice versa. */

        if (refs->ip_ver == -1)
           ref_quirks &= ((ts->ip_ver == IP_VER4) ? ~(QUIRK_FLOW) :
            ~(QUIRK_DF | QUIRK_NZ_ID | QUIRK_ZERO_ID));

        if (ref_quirks != ts->quirks) {

          u32 deleted = (ref_quirks ^ ts->quirks) & ref_quirks,
              added = (ref_quirks ^ ts->quirks) & ts->quirks;

          /* If there is a difference in quirks, but it amounts to 'df' or 'id+'
             disappearing, or 'id-' or 'ecn' appearing, allow a fuzzy match. */

          if (fmatch || (deleted & ~(QUIRK_DF | QUIRK_NZ_ID)) ||
              (added & ~(QUIRK_ZERO_ID | QUIRK_ECN))) continue;

          fuzzy = 1;

        }

        /* Fixed parameters. */

        if (refs->opt_eol_pad != ts->opt_eol_pad ||
            refs->ip_opt_len != ts->ip_opt_len) continue;

        /* TTL matching, with a provision to allow fuzzy match. */

        if (ref->bad_ttl) {

          if (refs->ttl < ts->ttl) continue;

        } else {

          if (refs->ttl < ts->ttl || refs->ttl - ts->ttl > MAX_DIST) fuzzy = 1;

        }

        /* Simple wildcards. */

        if (refs->mss != -1 && refs->mss != ts->mss) continue;
        if (refs->wscale != -1 && refs->wscale != ts->wscale) continue;
        if (refs->pay_class != -1 && refs->pay_class != ts->pay_class) continue;

        /* Window size. */

        if (ts->win_type != WIN_TYPE_NORMAL) {

          /* Comparing two p0f.fp signatures. */

          if (refs->win_type != ts->win_type || refs->win != ts->win) continue;

        } else {

          /* Comparing real-world stuff. */

          switch (refs->win_type) {

            case WIN_TYPE_NORMAL:
              if (refs->win != ts->win) continue;
              break;

            case WIN_TYPE_MOD:
              if (ts->win % refs->win) continue;
              break;

            case WIN_TYPE_MSS:
              if (use_mtu || refs->win != win_multi) continue;
              break;

            case WIN_TYPE_MTU:
              if (!use_mtu || refs->win != win_multi) continue;
              break;

            /* WIN_TYPE_ANY */

          }

        }

        /* Got a match? If not fuzzy, return. If fuzzy, keep looking. */

        if (!fuzzy) {

          if (!ref->generic) {

            ts->matched = ref;
            ts->fuzzy   = 0;
            ts->dist    = refs->ttl - ts->ttl;
            return;

          } else if (!gmatch) gmatch = ref;

        } else if (!fmatch) fmatch = ref;

    }

    /* OK, no definitive match so far... */
    if (dupe_det) return;
    /* If we found a generic signature, and nothing better, let's just use
     that. */

    if (gmatch) {

        ts->matched = gmatch;
        ts->fuzzy   = 0;
        ts->dist    = gmatch->sig->ttl - ts->ttl;
        return;

    }

    /* No fuzzy matching for userland tools. */

    if (fmatch && fmatch->class_id == -1) return;

    /* Let's try to guess distance if no match; or if match TTL out of
         range. */

    if (!fmatch || fmatch->sig->ttl < ts->ttl ||
           (!fmatch->bad_ttl && fmatch->sig->ttl - ts->ttl > MAX_DIST))
        ts->dist = guess_dist(ts->ttl);
    else
        ts->dist = fmatch->sig->ttl - ts->ttl;

    /* Record the outcome. */

    ts->matched = fmatch;
    if (fmatch) ts->fuzzy = 1;
}

/* Figure out if window size is a multiplier of MSS or MTU. We don't take window
   scaling into account, because neither do TCP stack developers. */

static s16 detect_win_multi(struct tcp_sig* ts, u8* use_mtu, u16 syn_mss) {

  u16 win = ts->win;
  s32 mss = ts->mss, mss12 = mss - 12;

  if (!win || mss < 100 || ts->win_type != WIN_TYPE_NORMAL)
    return -1;

#define RET_IF_DIV(_div, _use_mtu, _desc) do { \
    if ((_div) && !(win % (_div))) { \
      *use_mtu = (_use_mtu); \
      return win / (_div); \
    } \
  } while (0)

  RET_IF_DIV(mss, 0, "MSS");

  /* Some systems will sometimes subtract 12 bytes when timestamps are in use. */

  if (ts->ts1) RET_IF_DIV(mss12, 0, "MSS - 12");

  /* Some systems use MTU on the wrong interface, so let's check for the most
     common case. */

  RET_IF_DIV(1500 - MIN_TCP4, 0, "MSS (MTU = 1500, IPv4)");
  RET_IF_DIV(1500 - MIN_TCP4 - 12, 0, "MSS (MTU = 1500, IPv4 - 12)");

  if (ts->ip_ver == IP_VER6) {

    RET_IF_DIV(1500 - MIN_TCP6, 0, "MSS (MTU = 1500, IPv6)");
    RET_IF_DIV(1500 - MIN_TCP6 - 12, 0, "MSS (MTU = 1500, IPv6 - 12)");

  }

  /* Some systems use MTU instead of MSS: */

  RET_IF_DIV(mss + MIN_TCP4, 1, "MTU (IPv4)");
  RET_IF_DIV(mss + ts->tot_hdr, 1, "MTU (actual size)");
  if (ts->ip_ver == IP_VER6) RET_IF_DIV(mss + MIN_TCP6, 1, "MTU (IPv6)");
  RET_IF_DIV(1500, 1, "MTU (1500)");

  /* On SYN+ACKs, some systems use of the peer: */

  if (syn_mss) {

    RET_IF_DIV(syn_mss, 0, "peer MSS");
    RET_IF_DIV(syn_mss - 12, 0, "peer MSS - 12");

  }

#undef RET_IF_DIV

  return -1;

}


/* Figure out what the TTL distance might have been for an unknown sig. */

static u8 guess_dist(u8 ttl) {
    if (ttl <= 32) return 32 - ttl;
    if (ttl <= 64) return 64 - ttl;
    if (ttl <= 128) return 128 - ttl;
    return 255 - ttl;
}

void fingerprint_destroy_flow(MolochFpFlow_t **fflow)
{
    MolochFpFlow_t *f = *fflow;
    save_fp_result(&f->server);
    save_fp_result(&f->client);
    free(f->http_tmp);
    free(f);
    *fflow = NULL;
}

static void save_fp_result(MolochFpHost_t *host)
{
    if (!host->ip_ver) return;  //No host info
    MolochFpHost_t *found_host = lookup_host(host->addr, host->ip_ver);
    if (found_host) {
        if (update_host_change(found_host, host)) {
            moloch_db_save_fingerprint(host);
        }
        touch_host(found_host);
    }
    else {
        insert_host(host);
        moloch_db_save_fingerprint(host);
    }
}

static void remove_host(MolochFpHost_t *host)
{
    u32 bucket = get_host_bucket(host->addr, host->ip_ver);
    /* Remove from the bucket linked list */
    if (host->next) host->next->prev = host->prev;
    if (host->prev) host->prev->next = host->next;
    else host_b[bucket]= host->next;
    /* Remove from the by-age linked list */
    if (host->newer) host->newer->older = host->older;
    else newest_host = host->older;
    if (host->older) host->older->newer = host->newer;
    else host_by_age = host->newer;
    /* Free memory */
    free(host);
    host_cnt--;
}

/* Return 1 if host changed */
static int update_host_change(MolochFpHost_t *cur_host, MolochFpHost_t *new_host)
{
    int change = 0;
    if (strcmp(cur_host->os, new_host->os) != 0) {
        change = 1;
        strcpy(cur_host->os, new_host->os);
    }
    if (strcmp(cur_host->app, new_host->app) != 0) {
        change = 1;
        strcpy(cur_host->app, new_host->app);
    }
    if (strcmp(cur_host->link, new_host->link) != 0) {
        change = 1;
        strcpy(cur_host->link, new_host->link);
    }
    return change;
}

static void touch_host(MolochFpHost_t *host)
{
    pthread_mutex_lock(&mutex);
    if (host != newest_host) {
        host->newer->older = host->older;
        if (host->older) host->older->newer = host->newer;
        else host_by_age = host->newer;
        newest_host->newer = host;
        host->older = newest_host;
        host->newer = NULL;
        newest_host = host;
    }
    pthread_mutex_unlock(&mutex);
}

static void insert_host(MolochFpHost_t *new_host)
{
    pthread_mutex_lock(&mutex);
    u32 bucket = get_host_bucket(new_host->addr, new_host->ip_ver);
    MolochFpHost_t *nh;
    if (host_cnt > MAX_HOSTS)
        nuke_hosts();
    nh = (MolochFpHost_t *)calloc(sizeof(MolochFpHost_t), 1);
    nh->ip_ver = new_host->ip_ver;
    memcpy(nh->addr, new_host->addr, 16);
    if (host_b[bucket]) {
        nh->next = host_b[bucket];
        host_b[bucket]->prev = nh;
    }
    host_b[bucket] = nh;
    host_cnt++;

    /* Insert into the by-age linked list */
    if (newest_host) {
        newest_host->newer = nh;
        nh->older = newest_host;
    }
    else {
        host_by_age = nh;
    }
    newest_host = nh;
    pthread_mutex_unlock(&mutex);
}

/* Look up host data. */
MolochFpHost_t *lookup_host(char *addr, u8 ip_ver) {
    u32 bucket = get_host_bucket(addr, ip_ver);
    MolochFpHost_t *h = host_b[bucket];

    pthread_mutex_lock(&mutex);
    while (h) {
        if (ip_ver == h->ip_ver &&
            !memcmp(addr, h->addr, (h->ip_ver == IP_VER4) ? 4 : 16)) {
            pthread_mutex_unlock(&mutex);
            return h;
        }
        h = h->next;
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
}

/* Calculate hash bucket for host_data. */
static u32 get_host_bucket(char* addr, u8 ip_ver) {
    u32 bucket;
    bucket = hash32((u8*)addr, (ip_ver == IP_VER4) ? 4 : 16, hash_seed);
    return bucket % HOST_BUCKETS;
}


static MolochFpFlow_t *init_flow()
{
    MolochFpFlow_t *fflow = (MolochFpFlow_t *)calloc(sizeof(MolochFpFlow_t), 1);
    fflow->http_tmp = (struct http_sig *)calloc(sizeof(struct http_sig), 1);
    return fflow;
}

static void read_config(const char *fname)
{
    s32 f;
    struct stat st;
    u8  *data, *cur;

    f = open((char*)fname, O_RDONLY);
    if (f < 0) {
        LOG("FATAL Cannot open '%s' for reading.", fname);
        return;
    }

    if (fstat(f, &st)) {
        LOG("FATAL fstat() on '%s' failed.", fname);
        return;
    }

    if (!st.st_size) {
        close(f);
        goto end_fp_read;
    }

    cur = data = calloc(sizeof(u8), st.st_size + 1);

    if (read(f, data, st.st_size) != st.st_size) {
      LOG("Short read from '%s'.", fname);
      return;
    }
    data[st.st_size] = 0;
    close(f);

    /* If you put NUL in your p0f.fp... Well, sucks to be you. */
    while (1) {
        u8 *eol;
        conf.line_no++;
        while (isblank(*cur)) cur++;
        eol = cur;
        while (*eol && *eol != '\n') eol++;
        if (*cur != ';' && cur != eol) {
            u8 *line = (u8 *)malloc(sizeof(u8) * (eol - cur) + 1);
            memcpy(line, cur, eol - cur);
            line[eol - cur] = '\0';
            config_parse_line(line);
            free(line);
        }
        if (!*eol) break;
        cur = eol + 1;
    }
    free(data);
end_fp_read:
    if (!conf.sig_cnt)
        LOG("[!] No signatures found in '%s'.\n", fname);
    else
        LOG("[+] Loaded %u signature%s from '%s'.\n", conf.sig_cnt,
        conf.sig_cnt == 1 ? "" : "s", fname);
}

static void config_parse_line(u8* line) {
    u8 *val,*eon;
    /* Special handling for [module:direction]... */
    if (*line == '[') {
        u8* dir;
        line++;
        /* Simplified case for [mtu]. */

        if (!strcmp((char*)line, "mtu]")) {
            conf.mod_type = CF_MOD_MTU;
            conf.state = CF_NEED_LABEL;
            return;
        }
        dir = (u8*)strchr((char*)line, ':');
        if (!dir) {
            LOG("FATAL Malformed section identifier in line %u.", conf.line_no);
            return;
        }
        *dir = 0; dir++;
        if (!strcmp((char*)line, "tcp")) {
            conf.mod_type = CF_MOD_TCP;
        } else if (!strcmp((char*)line, "http")) {
            conf.mod_type = CF_MOD_HTTP;
        } else {
            LOG("FATAL Unrecognized fingerprinting module '%s' in line %u.", line, conf.line_no);
            return;
        }
        if (!strcmp((char*)dir, "request]")) {
            conf.mod_to_srv = 1;
        } else if (!strcmp((char*)dir, "response]")) {
            conf.mod_to_srv = 0;
        } else {
            LOG("FATAL Unrecognized traffic direction in line %u.", conf.line_no);
            return;
        }
        conf.state = CF_NEED_LABEL;
        return;
    }

    /* Everything else follows the 'name = value' approach. */
    val = line;
    while (isalpha(*val) || *val == '_') val++;
    eon = val;
    while (isblank(*val)) val++;
    if (line == val || *val != '=') {
        LOG("FATAL Unexpected statement in line %u.", conf.line_no);
        return;
    }
    while (isblank(*++val));
    *eon = 0;

    if (!strcmp((char*)line, "classes")) {
        if (conf.state != CF_NEED_SECT)  {
            LOG("FATAL misplaced 'classes' in line %u.", conf.line_no);
            return;
        }
        config_parse_classes(val);

    } else if (!strcmp((char*)line, "ua_os")) {
        if (conf.state != CF_NEED_LABEL || conf.mod_to_srv != 1 || conf.mod_type != CF_MOD_HTTP) { 
            LOG("FATAL misplaced 'us_os' in line %u.", conf.line_no);
            return;
        }
        http_parse_ua(val, conf.line_no);

    } else if (!strcmp((char*)line, "label")) {

        /* We will drop sig_sys / sig_flavor on the floor if no signatures
        actually created, but it's not worth tracking that. */

        if (conf.state != CF_NEED_LABEL && conf.state != CF_NEED_SIG) {
            LOG("FATAL misplaced 'label' in line %u.", conf.line_no);
            return;
        }
        config_parse_label((char *)val);

        if (conf.mod_type != CF_MOD_MTU && conf.sig_class < 0) conf.state = CF_NEED_SYS;
        else conf.state = CF_NEED_SIG;

    } else if (!strcmp((char*)line, "sys")) {
        if (conf.state != CF_NEED_SYS) {
            LOG("FATAL Misplaced 'sys' in line %u.", conf.line_no);
            return;
        }

        config_parse_sys(val);
        conf.state = CF_NEED_SIG;

    } else if (!strcmp((char*)line, "sig")) {
        if (conf.state != CF_NEED_SIG) {
            LOG("FATAL Misplaced 'sig' in line %u.", conf.line_no);
            return;
        }
        switch (conf.mod_type) {
        case CF_MOD_TCP:
            tcp_register_sig(conf.mod_to_srv, conf.generic, conf.sig_class, conf.sig_name, conf.sig_flavor,
                         conf.label_id, conf.cur_sys, conf.cur_sys_cnt, val, conf.line_no);
            break;
        case CF_MOD_MTU:
            mtu_register_sig(conf.sig_flavor, val, conf.line_no);
            break;
        case CF_MOD_HTTP:
            http_register_sig(conf.mod_to_srv, conf.generic, conf.sig_class, conf.sig_name, conf.sig_flavor,
                          conf.label_id, conf.cur_sys, conf.cur_sys_cnt, val, conf.line_no);
            break;

        }
        conf.sig_cnt++;
    } else {
        LOG("FATAL Unrecognized field '%s' in line %u.", line, conf.line_no);
        return;
    }

}

/* Parse 'classes' parameter by populating fp_os_classes. */
static void config_parse_classes(u8* val) {
    while (*val) {
        u8* nxt;

        while (isblank(*val) || *val == ',') val++;
        nxt = val;
        while (isalnum(*nxt)) nxt++;
        if (nxt == val || (*nxt && *nxt != ',')) {
            LOG("DEBUG Malformed class entry in line %u.", conf.line_no);
            return;
        }
        fp_os_classes = realloc(fp_os_classes, (conf.class_cnt + 1) * sizeof(u8*));
        fp_os_classes[conf.class_cnt++] = strndup((char*)val, nxt - val);
        val = nxt;
    }
}

/* Register new HTTP signature. */
void http_parse_ua(u8* val, u32 line_no) {

    u8* nxt;
    while (*val) {
        u32 id;
        char* name = NULL;
        nxt = val;
        while (*nxt && (isalnum(*nxt) || strchr(NAME_CHARS, *nxt))) nxt++;
        if (val == nxt) {
            LOG("FATAL Malformed system name in line %u.", line_no);
            return;
        }

        id = lookup_name_id((char *)val, nxt - val);
        val = nxt;
        if (*val == '=') {
            if (val[1] != '[') {
                LOG("Missing '[' after '=' in line %u.", line_no);
            }
            val += 2;
            nxt = val;
            while (*nxt && *nxt != ']') nxt++;
            if (val == nxt || !*nxt) {
                LOG("FATAL Malformed signature in line %u.", line_no);
                return;
            }
            name = strndup((char*)val, nxt - val);
            val = nxt + 1;
        }

        ua_map = realloc(ua_map, (ua_map_cnt + 1) *
                        sizeof(struct ua_map_record));
        ua_map[ua_map_cnt].id = id;

        if (!name) ua_map[ua_map_cnt].name = fp_os_names[id];
        else ua_map[ua_map_cnt].name = name;
        ua_map_cnt++;
        if (*val == ',') val++;
    }
}

/* Look up or create OS or application id. */
u32 lookup_name_id(char* name, u8 len) {
    u32 i;
    for (i = 0; i < conf.name_cnt; i++)
        if (!strncasecmp((char*)name, fp_os_names[i], len)
            && !fp_os_names[i][len]) break;
    if (i == conf.name_cnt) {
        conf.sig_name = conf.name_cnt;
        fp_os_names = realloc(fp_os_names, (conf.name_cnt + 1) * sizeof(char *));
        fp_os_names[conf.name_cnt++] = strndup(name, len);

    }
    return i;
}

/* Parse 'label' parameter by looking up ID and recording name / flavor. */
static void config_parse_label(char* val) {
    char* nxt;
    u32 i;

    /* Simplified handling for [mtu] signatures. */
    if (conf.mod_type == CF_MOD_MTU) {
        if (!*val) {
            LOG("FATAL Empty MTU label in line %u.\n", conf.line_no);
            return;
        }
        conf.sig_flavor = (u8*)strdup(val);
        return;
    }

    if (*val == 'g') conf.generic = 1;
    else if (*val == 's') conf.generic = 0;
    else {
        LOG("FATAL Malformed class entry in line %u.", conf.line_no);
        return;
    }

    if (val[1] != ':') {
        LOG("FATAL Malformed class entry in line %u.", conf.line_no);
    }
    val += 2;
    nxt = val;
    while (isalnum(*nxt) || *nxt == '!') nxt++;
    if (nxt == val || *nxt != ':') {
        LOG("FATAL Malformed class entry in line %u.", conf.line_no);
        return;
    }
    if (*val == '!' && val[1] == ':') {
        conf.sig_class = -1;
    } else {
        *nxt = 0;
        for (i = 0; i < conf.class_cnt; i++)
            if (!strcasecmp(val, (char*)fp_os_classes[i])) break;
        if (i == conf.class_cnt) {
            LOG("FATAL Unknown class '%s' in line %u.", val, conf.line_no);
            return;
        }
        conf.sig_class = i;
    }
    nxt++;
    val = nxt;
    while (isalnum(*nxt) || (*nxt && strchr(NAME_CHARS, *nxt))) nxt++;

    if (nxt == val || *nxt != ':') {
        LOG("FATAL Malformed name in line %u.", conf.line_no);
        return;
    }
    conf.sig_name = lookup_name_id(val, nxt - val);
    if (nxt[1]) conf.sig_flavor = (u8*)strdup(nxt + 1);
    else conf.sig_flavor = NULL;
    conf.label_id++;
}

/* Parse 'sys' parameter into cur_sys[]. */
static void config_parse_sys(u8* val) {
    if (conf.cur_sys) {
        conf.cur_sys = NULL;
        conf.cur_sys_cnt = 0;
    }
    while (*val) {
        u8* nxt;
        u8  is_cl = 0, orig;
        u32 i;

    while (isblank(*val) || *val == ',') val++;

    if (*val == '@') { is_cl = 1; val++; }
    nxt = val;
    while (isalnum(*nxt) || (*nxt && strchr(NAME_CHARS, *nxt))) nxt++;
    if (nxt == val || (*nxt && *nxt != ',')) {
        LOG("FATAL Malformed sys entry in line %u.", conf.line_no);
        return;
    }
    orig = *nxt;
    *nxt = 0;

    if (is_cl) {
        for (i = 0; i < conf.class_cnt; i++)
        if (!strcasecmp((char*)val, (char*)fp_os_classes[i])) break;
        if (i == conf.class_cnt) {
            LOG("FATAL Unknown class '%s' in line %u.", val, conf.line_no);
            return;
        }
        i |= SYS_CLASS_FLAG;
    } else {
        for (i = 0; i < conf.name_cnt; i++)
            if (!strcasecmp((char*)val, fp_os_names[i])) break;
        if (i == conf.name_cnt) {
            fp_os_names = realloc(fp_os_names, (conf.name_cnt + 1) * sizeof(char *));
            fp_os_names[conf.name_cnt++] = strndup((char *)val, nxt - val);
        }
    }
    conf.cur_sys = realloc(conf.cur_sys, (conf.cur_sys_cnt + 1) * 4);
    conf.cur_sys[conf.cur_sys_cnt++] = i;

    *nxt = orig;
    val = nxt;
    }
}

/* Register a new MTU signature. */
void mtu_register_sig(u8* name, u8* val, u32 line_no) {
    u8* nxt = val;
    s32 mtu;
    u32 bucket;

    while (isdigit(*nxt)) nxt++;
    if (nxt == val || *nxt) {
        LOG("FATAL Malformed MTU value in line %u.", line_no);
        return;
    }
    mtu = atol((char*)val);

    if (mtu <= 0 || mtu > 65535) {
        LOG("FATAL Malformed MTU value in line %u.", line_no);
        return;
    }
    bucket = mtu % SIG_BUCKETS;
    mtu_sigs[bucket] = realloc(mtu_sigs[bucket], (mtu_sig_cnt[bucket] + 1) *
                                sizeof(struct mtu_sig_record));

    mtu_sigs[bucket][mtu_sig_cnt[bucket]].mtu = mtu;
    mtu_sigs[bucket][mtu_sig_cnt[bucket]].name = name;
    mtu_sig_cnt[bucket]++;
}

/* Parse TCP-specific bits and register a signature read from p0f.fp. This
   function is too long. */
void tcp_register_sig(u8 to_srv, u8 generic, s32 sig_class, u32 sig_name,
                      u8* sig_flavor, u32 label_id, u32* sys, u32 sys_cnt,
                      u8* val, u32 line_no) {

    s8  ver, win_type, pay_class;
    u8  opt_layout[MAX_TCP_OPT];
    u8  opt_cnt = 0, bad_ttl = 0;

    s32 ittl, olen, mss, win, scale, opt_eol_pad = 0;
    u32 quirks = 0, bucket, opt_hash;

    u8* nxt;

    struct tcp_sig* tsig;
    struct tcp_sig_record* trec;

//  /* IP version */
    switch (*val) {
      case '4': ver = IP_VER4; break;
      case '6': ver = IP_VER6; break;
      case '*': ver = -1; break;
      default:
        LOG("FATAL Unrecognized IP version in line %u.", line_no);
        return;
    }
    if (val[1] != ':'){
        LOG("FATAL Malformed signature in line %u.", line_no);
        return;
    }
    val += 2;

    /* Initial TTL (possibly ttl+dist or ttl-) */
    nxt = val;
    while (isdigit(*nxt)) nxt++;

    if (*nxt != ':' && *nxt != '+' && *nxt != '-') {
        LOG("FATAL Malformed signature in line %u.", line_no);
        return;
    }

    ittl = atol((char*)val);
    if (ittl < 1 || ittl > 255) {
        LOG("FATAL Bogus initial TTL in line %u.", line_no);
        return;
    }
    val = nxt + 1;

    if (*nxt == '-' && nxt[1] == ':') {

      bad_ttl = 1;
      val += 2;

    } else if (*nxt == '+') {
        s32 ittl_add;
        nxt++;
        while (isdigit(*nxt)) nxt++;
        if (*nxt != ':') {
            LOG("Malformed signature in line %u.", line_no);
            return;
        }
        ittl_add = atol((char*)val);
        if (ittl_add < 0 || ittl + ittl_add > 255) {
          LOG("Bogus initial TTL in line %u.", line_no);
          return;
        }

        ittl += ittl_add;
        val = nxt + 1;

    }
    /* Length of IP options */
    nxt = val;
    while (isdigit(*nxt)) nxt++;
    if (*nxt != ':') {
        LOG("FATAL Malformed signature in line %u.", line_no);
        return;
    }

    olen = atol((char*)val);
    if (olen < 0 || olen > 255) {
        LOG("Bogus IP option length in line %u.", line_no);
        return;
    }

    val = nxt + 1;

    /* MSS */
    if (*val == '*' && val[1] == ':') {
        mss = -1;
        val += 2;
    } else {
        nxt = val;
        while (isdigit(*nxt)) nxt++;
        if (*nxt != ':') {
            LOG("Malformed signature in line %u.", line_no);
            return;
        }
        mss = atol((char*)val);
        if (mss < 0 || mss > 65535) {
            LOG("Bogus MSS in line %u.", line_no);
            return;
        }
        val = nxt + 1;
    }
    /* window size, followed by comma */
     if (*val == '*' && val[1] == ',') {
         win_type = WIN_TYPE_ANY;
         win = 0;
         val += 2;
     } else if (*val == '%') {
         win_type = WIN_TYPE_MOD;
         val++;
         nxt = val;
         while (isdigit(*nxt)) nxt++;
         if (*nxt != ',') {
             LOG("FATAL Malformed signature in line %u.", line_no);
             return;
         }
         win = atol((char*)val);
         if (win < 2 || win > 65535) {
             LOG("Bogus '%%' value in line %u.", line_no);
             return;
         }
         val = nxt + 1;
    } else if (!strncmp((char*)val, "mss*", 4) ||
               !strncmp((char*)val, "mtu*", 4)) {
        win_type = (val[1] == 's') ? WIN_TYPE_MSS : WIN_TYPE_MTU;
        val += 4;
        nxt = val;
        while (isdigit(*nxt)) nxt++;
        if (*nxt != ',') {
            LOG("FATAL Malformed signature in line %u.", line_no);
            return;
        }
        win = atol((char*)val);
        if (win < 1 || win > 1000) {
            LOG("FATAL Bogus MSS/MTU multiplier in line %u.", line_no);
            return;
        }
        val = nxt + 1;

    } else {
        win_type = WIN_TYPE_NORMAL;
        nxt = val;
        while (isdigit(*nxt)) nxt++;
        if (*nxt != ',') {
            LOG("FATAL Malformed signature in line %u.", line_no);
            return;
        }
        win = atol((char*)val);
        if (win < 0 || win > 65535) {
            LOG("FATAL Bogus window size in line %u.", line_no);
            return;
        }
        val = nxt + 1;
    }

    /* Window scale */
    if (*val == '*' && val[1] == ':') {
        scale = -1;
        val += 2;
    } else {
        nxt = val;
        while (isdigit(*nxt)) nxt++;
        if (*nxt != ':') {
            LOG("Malformed signature in line %u.", line_no);
            return;
        }

        scale = atol((char*)val);
        if (scale < 0 || scale > 255) {
            LOG("Bogus window scale in line %u.", line_no);
            return;
        }
        val = nxt + 1;
    }
    /* Option layout */
    memset(opt_layout, 0, sizeof(opt_layout));  
    while (*val != ':') {
        if (opt_cnt >= MAX_TCP_OPT) {
            LOG("FATAL Too many TCP options in line %u.", line_no);
            return;
        }
        if (!strncmp((char*)val, "eol", 3)) {
            opt_layout[opt_cnt++] = TCPOPT_EOL;
            val += 3;

            if (*val != '+') {
                LOG("FATAL Malformed EOL option in line %u.", line_no);
                return;
            }
            val++;
            nxt = val;
            while (isdigit(*nxt)) nxt++;
            if (!*nxt) {
                LOG("FATAL Truncated options in line %u.", line_no);
                return;
            }

            if (*nxt != ':') {
                LOG("FATAL EOL must be the last option in line %u.", line_no);
                return;
            }
            opt_eol_pad = atol((char*)val);
            if (opt_eol_pad < 0 || opt_eol_pad > 255) {
                LOG("FATAL Bogus EOL padding in line %u.", line_no);
                return;
            }
            val = nxt;
        } else if (!strncmp((char*)val, "nop", 3)) {
            opt_layout[opt_cnt++] = TCPOPT_NOP;
            val += 3;

        } else if (!strncmp((char*)val, "mss", 3)) {
            opt_layout[opt_cnt++] = TCPOPT_MAXSEG;
            val += 3;
        } else if (!strncmp((char*)val, "ws", 2)) {
            opt_layout[opt_cnt++] = TCPOPT_WSCALE;
            val += 2;
        } else if (!strncmp((char*)val, "sok", 3)) {
            opt_layout[opt_cnt++] = TCPOPT_SACKOK;
            val += 3;
        } else if (!strncmp((char*)val, "sack", 4)) {
            opt_layout[opt_cnt++] = TCPOPT_SACK;
            val += 4;
        } else if (!strncmp((char*)val, "ts", 2)) {
            opt_layout[opt_cnt++] = TCPOPT_TSTAMP;
            val += 2;
        } else if (*val == '?') {
            s32 optno;
            val++;
            nxt = val;
            while (isdigit(*nxt)) nxt++;

            if (*nxt != ':' && *nxt != ',') {
                LOG("FATAL Malformed '?' option in line %u.", line_no);
                return;
            }
            optno = atol((char*)val);
            if (optno < 0 || optno > 255) {
                LOG("FATAL Bogus '?' option in line %u.", line_no);
                return;
            }
            opt_layout[opt_cnt++] = optno;
            val = nxt;
        } else {
            LOG("FATAL Unrecognized TCP option in line %u.", line_no);
            return;
        }
        if (*val == ':') break;
        if (*val != ',') {
            LOG("FATAL Malformed TCP options in line %u.", line_no);
            return;
        }
        val++;
    }
    val++;
    opt_hash = hash32(opt_layout, opt_cnt, hash_seed);
    /* Quirks */
    while (*val != ':') {
        if (!strncmp((char*)val, "df", 2)) {
            if (ver == IP_VER6) {
                LOG("'df' is not valid for IPv6 in line %d.", line_no);
                return;
            }
            quirks |= QUIRK_DF;
            val += 2;
        } else if (!strncmp((char*)val, "id+", 3)) {
            if (ver == IP_VER6) {
                LOG("FATAL 'id+' is not valid for IPv6 in line %d.", line_no);
                return;
            }
            quirks |= QUIRK_NZ_ID;
            val += 3;
        } else if (!strncmp((char*)val, "id-", 3)) {
            if (ver == IP_VER6) {
                LOG("FATAL 'id-' is not valid for IPv6 in line %d.", line_no);
                return;
            }
            quirks |= QUIRK_ZERO_ID;
            val += 3;
        } else if (!strncmp((char*)val, "ecn", 3)) {
            quirks |= QUIRK_ECN;
            val += 3;
        } else if (!strncmp((char*)val, "0+", 2)) {
            if (ver == IP_VER6) {
                LOG("FATAL '0+' is not valid for IPv6 in line %d.", line_no);
                return;
            }
            quirks |= QUIRK_NZ_MBZ;
            val += 2;
        } else if (!strncmp((char*)val, "flow", 4)) {
            if (ver == IP_VER4) {
                LOG("FATAL 'flow' is not valid for IPv4 in line %d.", line_no);
                return;
            }
            quirks |= QUIRK_FLOW;
            val += 4;
        } else if (!strncmp((char*)val, "seq-", 4)) {
            quirks |= QUIRK_ZERO_SEQ;
            val += 4;
        } else if (!strncmp((char*)val, "ack+", 4)) {
            quirks |= QUIRK_NZ_ACK;
            val += 4;
        } else if (!strncmp((char*)val, "ack-", 4)) {
            quirks |= QUIRK_ZERO_ACK;
            val += 4;
        } else if (!strncmp((char*)val, "uptr+", 5)) {
            quirks |= QUIRK_NZ_URG;
            val += 5;
        } else if (!strncmp((char*)val, "urgf+", 5)) {
            quirks |= QUIRK_URG;
            val += 5;
        } else if (!strncmp((char*)val, "pushf+", 6)) {
            quirks |= QUIRK_PUSH;
            val += 6;
        } else if (!strncmp((char*)val, "ts1-", 4)) {
            quirks |= QUIRK_OPT_ZERO_TS1;
            val += 4;
        } else if (!strncmp((char*)val, "ts2+", 4)) {
            quirks |= QUIRK_OPT_NZ_TS2;
            val += 4;
        } else if (!strncmp((char*)val, "opt+", 4)) {
            quirks |= QUIRK_OPT_EOL_NZ;
            val += 4;
        } else if (!strncmp((char*)val, "exws", 4)) {
            quirks |= QUIRK_OPT_EXWS;
            val += 4;
        } else if (!strncmp((char*)val, "bad", 3)) {
            quirks |= QUIRK_OPT_BAD;
            val += 3;
        } else {
            LOG("FATAL Unrecognized quirk in line %u.", line_no);
            return;
        }
        if (*val == ':') break;
        if (*val != ',') {
            LOG("FATAL Malformed quirks in line %u.", line_no);
            return;
        }
        val++;
    }
    val++;
   /* Payload class */
    if (!strcmp((char*)val, "*")) pay_class = -1;
    else if (!strcmp((char*)val, "0")) pay_class = 0;
    else if (!strcmp((char*)val, "+")) pay_class = 1;
    else {
        LOG("FATAL Malformed payload class in line %u.", line_no);
        return;
    }

    /* Phew, okay, we're done. Now, create tcp_sig... */

    tsig = calloc(sizeof(struct tcp_sig), 1);

    tsig->opt_hash    = opt_hash;
    tsig->opt_eol_pad = opt_eol_pad;

    tsig->quirks      = quirks;

    tsig->ip_opt_len  = olen;
    tsig->ip_ver      = ver;
    tsig->ttl         = ittl;

    tsig->mss         = mss;
    tsig->win         = win;
    tsig->win_type    = win_type;
    tsig->wscale      = scale;
    tsig->pay_class   = pay_class;

    /* No need to set ts1, recv_ms, match, fuzzy, dist */
    tcp_find_match(to_srv, tsig, 1, 0);

    if (tsig->matched) {
      LOG("FATAL Signature in line %u is already covered by line %u.",
            line_no, tsig->matched->line_no);
    }
    /* Everything checks out, so let's register it. */
    bucket = opt_hash % SIG_BUCKETS;
    tcp_sigs[to_srv][bucket] = realloc(tcp_sigs[to_srv][bucket],
      (tcp_sig_cnt[to_srv][bucket] + 1) * sizeof(struct tcp_sig_record));
    trec = tcp_sigs[to_srv][bucket] + tcp_sig_cnt[to_srv][bucket];
    tcp_sig_cnt[to_srv][bucket]++;

    trec->generic  = generic;
    trec->class_id = sig_class;
    trec->name_id  = sig_name;
    trec->flavor   = sig_flavor;
    trec->label_id = label_id;
    trec->sys      = sys;
    trec->sys_cnt  = sys_cnt;
    trec->line_no  = line_no;
    trec->sig      = tsig;
    trec->bad_ttl  = bad_ttl;

  /* All done, phew. */
}

/* Convert IPv4 or IPv6 address to a human-readable form. */
char* addr_to_str(u8* data, u8 ip_ver) {
    static char tmp[128];
    /* We could be using inet_ntop(), but on systems that have older libc
     but still see passing IPv6 traffic, we would be in a pickle. */
    if (ip_ver == IP_VER4) {
        sprintf(tmp, "%u.%u.%u.%u", data[0], data[1], data[2], data[3]);
    } else {
    sprintf(tmp, "%x:%x:%x:%x:%x:%x:%x:%x",
            (data[0] << 8) | data[1], (data[2] << 8) | data[3],
            (data[4] << 8) | data[5], (data[6] << 8) | data[7],
            (data[8] << 8) | data[9], (data[10] << 8) | data[11],
            (data[12] << 8) | data[13], (data[14] << 8) | data[15]);
    }
    return tmp;
}

static void nuke_hosts(void)
{
    u32 kcnt = 1 + (host_cnt * 10 / 100);   //Kill 10% of hosts
    MolochFpHost_t *target = host_by_age;
    LOG("Nuke host, host count : %u", host_cnt);
    while (kcnt && target) {
        MolochFpHost_t *next = target->newer;
        remove_host(target);
        kcnt--;
        target = next;
    }
}

/* Register new HTTP signature. */
void http_register_sig(u8 to_srv, u8 generic, s32 sig_class, u32 sig_name,
                       u8* sig_flavor, u32 label_id, u32* sys, u32 sys_cnt,
                       u8* val, u32 line_no) {

    struct http_sig* hsig;
    struct http_sig_record* hrec;

    u8* nxt;

    hsig = calloc(sizeof(struct http_sig), 1);

    http_sigs[to_srv] = realloc(http_sigs[to_srv], sizeof(struct http_sig_record) *
    (http_sig_cnt[to_srv] + 1));

    hrec = &http_sigs[to_srv][http_sig_cnt[to_srv]];
    if (val[1] != ':') {
        LOG("FATAL Malformed signature in line %u.", line_no);
        return;
    }

    /* http_ver */
    switch (*val) {
        case '0': break;
        case '1': hsig->http_ver = 1; break;
        case '*': hsig->http_ver = -1; break;
        default:
            LOG("FATAL Bad HTTP version in line %u.", line_no);
            return;
    }

    val += 2;
    /* horder */
    while (*val != ':') {
        u32 id;
        u8 optional = 0;

        if (hsig->hdr_cnt >= HTTP_MAX_HDRS) {
            LOG("FATAL Too many headers listed in line %u.", line_no);
            return;
        }
        nxt = val;
        if (*nxt == '?') { optional = 1; val++; nxt++; }

        while (isalnum(*nxt) || *nxt == '-' || *nxt == '_') nxt++;
        if (val == nxt) {
            LOG("FATAL Malformed header name in line %u.", line_no);
            return;
        }

        id = lookup_hdr(val, nxt - val, 1);

        hsig->hdr[hsig->hdr_cnt].id = id;
        hsig->hdr[hsig->hdr_cnt].optional = optional;

        if (!optional) hsig->hdr_bloom4 |= bloom4_64(id);
        val = nxt;
        if (*val == '=') {
            if (val[1] != '[') {
                LOG("FATAL Missing '[' after '=' in line %u.", line_no);
                return;
            }
            val += 2;
            nxt = val;
            while (*nxt && *nxt != ']') nxt++;
            if (val == nxt || !*nxt) {
                LOG("FATAL Malformed signature in line %u.", line_no);
                return;
            }
            hsig->hdr[hsig->hdr_cnt].value = strndup(val, nxt - val);
            val = nxt + 1;
        }
        hsig->hdr_cnt++;
        if (*val == ',') val++; else if (*val != ':') {
            LOG("FATAL Malformed signature in line %u.", line_no);
            return;
        }
    }
    val++;
    /* habsent */
    while (*val != ':') {
        u32 id;
        if (hsig->miss_cnt >= HTTP_MAX_HDRS) {
            LOG("FATAL Too many headers listed in line %u.", line_no);
            return;
        }
        nxt = val;
        while (isalnum(*nxt) || *nxt == '-' || *nxt == '_') nxt++;

        if (val == nxt) {
            LOG("FATAL Malformed header name in line %u.", line_no);
            return;
        }
        id = lookup_hdr(val, nxt - val, 1);
        hsig->miss[hsig->miss_cnt] = id;
        val = nxt;
        hsig->miss_cnt++;
        if (*val == ',') val++; else if (*val != ':') {
            LOG("FATAL Malformed signature in line %u.", line_no);
            return;
        }

    }
    val++;
    /* exp_sw */
    if (*val) {
        if (strchr((char*)val, ':')) {
            LOG("FATAL Malformed signature in line %u.", line_no);
            return;
        }
        hsig->sw = strdup(val);
    }
    http_find_match(to_srv, hsig, 1);

    if (hsig->matched) {
        LOG("FATAL Signature in line %u is already covered by line %u.",
              line_no, hsig->matched->line_no);
        return;
    }

    hrec->class_id = sig_class;
    hrec->name_id  = sig_name;
    hrec->flavor   = sig_flavor;
    hrec->label_id = label_id;
    hrec->sys      = sys;
    hrec->sys_cnt  = sys_cnt;
    hrec->line_no  = line_no;
    hrec->generic  = generic;
    hrec->sig      = hsig;
    http_sig_cnt[to_srv]++;
}

/* Look up or register new http header */
static s32 lookup_hdr(u8* name, u32 len, u8 create) {
    u32  bucket = hash32(name, len, hash_seed) % SIG_BUCKETS;
    u32* p = hdr_by_hash[bucket];
    u32  i = hbh_cnt[bucket];

    while (i--) {
      if (!memcmp(hdr_names[*p], name, len) &&
          !hdr_names[*p][len]) return *p;
      p++;
    }

    /* Not found! */
    if (!create) return -1;

    hdr_names = realloc(hdr_names, (hdr_cnt + 1) * sizeof(u8*));
    hdr_names[hdr_cnt] = strndup(name, len);

    hdr_by_hash[bucket] = realloc(hdr_by_hash[bucket],
        (hbh_cnt[bucket] + 1) * 4);
    hdr_by_hash[bucket][hbh_cnt[bucket]++] = hdr_cnt++;

    return hdr_cnt - 1;
}

/* Ghetto Bloom filter 4-out-of-64 bitmask generator for adding 32-bit header
   IDs to a set. We expect around 10 members in a set. */
static inline u64 bloom4_64(u32 val) {
    u32 hash = hash32(&val, 4, hash_seed);
    u64 ret;
    ret = (1LL << (hash & 63));
    ret ^= (1LL << ((hash >> 8) & 63));
    ret ^= (1LL << ((hash >> 16) & 63));
    ret ^= (1LL << ((hash >> 24) & 63));
    return ret;
}

/* Find match for a signature. */
static void http_find_match(u8 to_srv, struct http_sig* ts, u8 dupe_det) {
    struct http_sig_record* gmatch = NULL;
    struct http_sig_record* ref = http_sigs[to_srv];
    u32 cnt = http_sig_cnt[to_srv];

    while (cnt--) {
        struct http_sig* rs = ref->sig;
        u32 ts_hdr = 0, rs_hdr = 0;
        if (rs->http_ver != -1 && rs->http_ver != ts->http_ver) goto next_sig;
        /* Check that all the headers listed for the p0f.fp signature (probably)
           appear in the examined traffic. */
        if ((ts->hdr_bloom4 & rs->hdr_bloom4) != rs->hdr_bloom4) goto next_sig;

        /* Confirm the ordering and values of headers (this is relatively
         slow, hence the Bloom filter first). */
        while (rs_hdr < rs->hdr_cnt) {
            u32 orig_ts = ts_hdr;
            while (rs->hdr[rs_hdr].id != ts->hdr[ts_hdr].id &&
                ts_hdr < ts->hdr_cnt) ts_hdr++;
            if (ts_hdr == ts->hdr_cnt) {
                if (!rs->hdr[rs_hdr].optional) goto next_sig;
                /* If this is an optional header, check that it doesn't appear
                   anywhere else. */
                for (ts_hdr = 0; ts_hdr < ts->hdr_cnt; ts_hdr++)
                    if (rs->hdr[rs_hdr].id == ts->hdr[ts_hdr].id) goto next_sig;
                ts_hdr = orig_ts;
                rs_hdr++;
                continue;
            }
            if (rs->hdr[rs_hdr].value &&
                (!ts->hdr[ts_hdr].value ||
                !strstr((char*)ts->hdr[ts_hdr].value,
                (char*)rs->hdr[rs_hdr].value))) goto next_sig;

            ts_hdr++;
            rs_hdr++;
        }
        /* Check that the headers forbidden in p0f.fp don't appear in the traffic.
            We first check if they seem to appear in ts->hdr_bloom4, and only if so,
            we do a full check. */
        for (rs_hdr = 0; rs_hdr < rs->miss_cnt; rs_hdr++) {
            u64 miss_bloom4 = bloom4_64(rs->miss[rs_hdr]);
            if ((ts->hdr_bloom4 & miss_bloom4) != miss_bloom4) continue;
            /* Okay, possible instance of a banned header - scan list... */
            for (ts_hdr = 0; ts_hdr < ts->hdr_cnt; ts_hdr++)
                if (rs->miss[rs_hdr] == ts->hdr[ts_hdr].id) goto next_sig;
        }
        /* When doing dupe detection, we want to allow a signature with additional
           banned headers to precede one with fewer, or with a different set. */
        if (dupe_det) {
            if (rs->miss_cnt > ts->miss_cnt) goto next_sig;
            for (rs_hdr = 0; rs_hdr < rs->miss_cnt; rs_hdr++) {
                for (ts_hdr = 0; ts_hdr < ts->miss_cnt; ts_hdr++)
                    if (rs->miss[rs_hdr] == ts->miss[ts_hdr]) break;
                /* One of the reference headers doesn't appear in current sig! */
                if (ts_hdr == ts->miss_cnt) goto next_sig;
            }
        }
        /* Whoa, a match. */
        if (!ref->generic) {
            ts->matched = ref;
            if (rs->sw && ts->sw && !strstr((char*)ts->sw, (char*)rs->sw))
            ts->dishonest = 1;
            return;
        } else if (!gmatch) gmatch = ref;
next_sig:
        ref = ref + 1;
    }
    /* A generic signature is the best we could find. */
    if (!dupe_det && gmatch) {
        ts->matched = gmatch;
        if (gmatch->sig->sw && ts->sw && !strstr((char*)ts->sw,
            (char*)gmatch->sig->sw)) ts->dishonest = 1;
    }
}

/* Parse HTTP date field. */
static u32 parse_date(u8* str) {
    struct tm t;
    if (!strptime((char*)str, "%a, %d %b %Y %H:%M:%S %Z", &t)) {
        LOG("DEBUG [#] Invalid 'Date' field ('%s').\n", str);
        return 0;
    }
    return mktime(&t);
}

/* Look up HTTP signature, create an observation. */
static void process_http(u8 to_srv, MolochFpFlow_t *f) {
    struct http_sig_record* m;
    u8* lang = NULL;

    MolochFpHost_t *host = (to_srv ? &f->client : &f->server);
    struct http_sig *http_tmp = (struct http_sig *)f->http_tmp;
    http_find_match(to_srv, http_tmp, 0);
    if ((m = http_tmp->matched)) {
        if (m->class_id < 0) {
            sprintf(host->app, "%s%s%s", fp_os_names[m->name_id], m->flavor ? " " : "", m->flavor ? m->flavor : (u8*)"");
        }
        else {
            sprintf(host->os, "%s%s%s", fp_os_names[m->name_id], m->flavor ? " " : "", m->flavor ? m->flavor : (u8*)"");
        }
    } else {
        host->app[0] = '\0';
    }

    if (http_tmp->lang && isalpha(http_tmp->lang[0]) &&
        isalpha(http_tmp->lang[1]) && !isalpha(http_tmp->lang[2])) {
        u8 lh = LANG_HASH(http_tmp->lang[0], http_tmp->lang[1]);
        u8 pos = 0;
        while (languages[lh][pos]) {
            if (http_tmp->lang[0] == languages[lh][pos][0] &&
                http_tmp->lang[1] == languages[lh][pos][1]) break;
            pos += 2;
        }
        if (!languages[lh][pos])
            host->lang[0] = '\0';
        else sprintf(host->lang, "%s", (lang = (u8*)languages[lh][pos + 1]));
    } else {
        host->lang[0] = '\0';
    }
}

/* Free up any allocated strings in http_sig. */
void free_sig_hdrs(struct http_sig* h) {
    u32 i;
    for (i = 0; i < h->hdr_cnt; i++) {
        if (h->hdr[i].name) free(h->hdr[i].name);
        if (h->hdr[i].value) free(h->hdr[i].value);
    }
}
