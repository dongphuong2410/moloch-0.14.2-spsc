#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl_wrapper.h>

#include "types.h"
#include "p0f.h"
#include "debug.h"
#include "handler.h"
#include "alloc-inl.h"
#include "storefp.h"

#define MAX_STRLEN  1024
#define DFT_HOST "127.0.0.1:9200"
#define BULK_BUF (1024 * 256)


static char es_host[MAX_STRLEN] = {0};

static void fp_flush(struct _p0fhdlr *hdlr);

void store_fp_init(p0fhdlr *hdlr)
{
    if (strlen(es_host) > 0) {
        hdlr->es_conn_desc = http_init(es_host);
    }
    else {
        hdlr->es_conn_desc = http_init(DFT_HOST);
    }
    hdlr->es_buffer = malloc(BULK_BUF * sizeof(char));
}

void store_fp_set_host(const char *host)
{
    strcpy(es_host, host);
}

void store_fp_destroy(struct _p0fhdlr *hdlr)
{
    fp_flush(hdlr);
    http_destroy(hdlr->es_conn_desc);
    free(hdlr->es_buffer);
}

void store_fp_write_fp(p0fhdlr *hdlr, const u8 *host, const u8 *os, const u8 *flavor)
{
    strcpy((char *)hdlr->buff[hdlr->buff_cnt].host, (const char *)host);
    strcpy((char *)hdlr->buff[hdlr->buff_cnt].os, (const char *)os);
    strcpy((char *)hdlr->buff[hdlr->buff_cnt].flavor, (const char *)(flavor ? flavor : (u8 *)""));
    hdlr->buff_cnt++;

    if (hdlr->buff_cnt == ES_BUFF_SIZE) {
        fp_flush(hdlr);
    }
}

static void fp_flush(struct _p0fhdlr *hdlr)
{
    char *sendmsg;
    char buff[MAX_STRLEN];
    int i;

    if (hdlr->buff_cnt == 0) return;
    sendmsg = ck_alloc(MAX_STRLEN * hdlr->buff_cnt);
    for (i = 0; i < hdlr->buff_cnt; i++) {
        sprintf(buff, "{\"index\":{\"_index\":\"fingerprint\","
                "\"_type\":\"fingerprint\"}}\n"
                "{\"host\":\"%s\","
                "\"os\":\"%s\","
                "\"flavor\":\"%s\"}\n",
                hdlr->buff[i].host,
                hdlr->buff[i].os,
                hdlr->buff[i].flavor);
        strcat(sendmsg, buff);
    }
    hdlr->buff_cnt = 0;
    http_param_set(hdlr->es_conn_desc, CURL_WRAPPER_POST, "/_bulk", sendmsg, NULL);
    http_send(hdlr->es_conn_desc, NULL);
    http_reuse(hdlr->es_conn_desc);
    ck_free(sendmsg);
}
