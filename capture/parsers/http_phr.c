/* Copyright 2012-2016 AOL Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this Software except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "moloch.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <zmq.h>
#include "picohttpparser.h"
#include "file_manager.h"
#include "multipart_parser.h"
#include "common.h"

//#define HTTPDEBUG 1

#define MAX_URL_LENGTH 4096
#define MAX_HTTP_HEADERS 100

enum http_type{
    HTTP_NONE,
    HTTP_REQ,
    HTTP_RES,
};

typedef struct {
    struct phr_header   *hdr[MAX_HTTP_HEADERS];
    short       pos[MAX_HTTP_HEADERS];
} HTTPSaveHeader;

typedef struct {
    char uri[URL_LEN];
    char host[STR_LEN];
    char filepath[STR_LEN];
    char range[STR_LEN];
    char content_type[STR_LEN];
    size_t filesize;
    int  status_code;
} zmqdata_t;

typedef struct {
    MolochSession_t *session;
    GString         *urlString;
    GString         *hostString;
    GString         *rangeString;
    GString         *contentTypeString;
    GString         *cookieString;
    GString         *authString;
    size_t          content_len;
    fm_t            *fm[2];
    zmqdata_t       zmqdata;
    int             is_multipart;

    //GChecksum       *checksum[2];

    uint16_t         wParsers:2;
    uint16_t         inHeader:2;
    uint16_t         reqWhich:1;
    uint16_t         which:1;

    multipart_parser *parser;
    multipart_parser_settings callbacks;

    /* for pico http parses */
    const char      *method_p;
    size_t          method_len;
    const char      *url_p;
    size_t          url_len;
    int             status_code;
    const char      *msg;
    size_t          msg_len;
    int             minor_version[2];
    struct phr_header   phr_headers[2][MAX_HTTP_HEADERS];
    size_t          phr_headers_num[2];
    int             prev_req_len[2];
    GString         *pkt_buffer[2];
    HTTPSaveHeader  save_header[2];
    int             save_headers_num[2];
    int             filecount;
    /* for pico http parses */
} HTTPInfo_t;

void _partial_file_complete(void *data);
static void _http_extract(void *data);
int _on_part_data_begin(multipart_parser *p);
int _on_part_data(multipart_parser *p, const char *at, size_t length);
int _on_part_data_end(multipart_parser *p);
void _process_http_payload(HTTPInfo_t *http, const char *buff, size_t buflen);

extern MolochConfig_t        config;
static http_parser_settings  parserSettings;
extern uint32_t              pluginsCbs;
static MolochStringHashStd_t httpReqHeaders;
static MolochStringHashStd_t httpResHeaders;

static int cookieKeyField;
static int cookieValueField;
static int hostField;
static int userField;
static int atField;
static int attachIdField;
static int urlsField;
static int xffField;
static int uaField;
static int tagsReqField;
static int tagsResField;
//static int md5Field;
static int verReqField;
static int verResField;
static int pathField;
static int keyField;
static int valueField;
//static int magicField;
static int statuscodeField;
static int methodField;

char *zmq_url = "tcp://127.0.0.1:5555";
char *ROOTPATH = "/home/meo/test";

/******************************************************************************/
void
moloch_http_parse_authorization(MolochSession_t *session, char *str)
{
    gsize olen;

    while (isspace(*str)) str++;

    char *space = strchr(str, ' ');

    if (!space)
        return;

    char *lower = g_ascii_strdown(str, space-str);
    if (!moloch_field_string_add(atField, session, lower, space-str, FALSE)) {
        g_free(lower);
    }

    if (strncasecmp("basic", str, 5) == 0) {
        str += 5;
        while (isspace(*str)) str++;

        // Yahoo reused Basic
        if (memcmp("token=", str, 6) != 0) {
            g_base64_decode_inplace(str, &olen);
            char *colon = strchr(str, ':');
            if (colon)
                *colon = 0;
            moloch_field_string_add(userField, session, str, -1, TRUE);
        }
    } else if (strncasecmp("digest", str, 6) == 0) {
        str += 5;
        while (isspace(*str)) str++;

        char *username = strstr(str, "username");
        if (!username) return;
        str = username + 8;
        while (isspace(*str)) str++;
        if (*str != '=') return;
        str++; // equal
        while (isspace(*str)) str++;

        int quote = 0;
        if (*str == '"') {
            quote = 1;
            str++;
        }
        char *end = str;
        while (*end && (*end != '"' || !quote) && (*end != ',' || quote)) {
            end++;
        }
        moloch_field_string_add(userField, session, str, end - str, TRUE);
    }
}
/******************************************************************************/
void
http_add_value(MolochSession_t *session, HTTPInfo_t *http)
{
    int which = http->which;
    int i;
    for (i = 0; i < http->save_headers_num[which]; i++){
        int pos = http->save_header[which].pos[i];
        const char  *s  = http->save_header[which].hdr[i]->value;
        int l   = http->save_header[which].hdr[i]->value_len;

        switch (config.fields[pos]->type) {
            case MOLOCH_FIELD_TYPE_INT:
            case MOLOCH_FIELD_TYPE_INT_ARRAY:
            case MOLOCH_FIELD_TYPE_INT_HASH:
            case MOLOCH_FIELD_TYPE_INT_GHASH:
                moloch_field_int_add(pos, session, atoi(s));
                break;
            case MOLOCH_FIELD_TYPE_STR:
            case MOLOCH_FIELD_TYPE_STR_ARRAY:
            case MOLOCH_FIELD_TYPE_STR_HASH:
                moloch_field_string_add(pos, session, s, l, TRUE);
                break;
            case MOLOCH_FIELD_TYPE_IP_HASH:
            case MOLOCH_FIELD_TYPE_IP_GHASH:
                {
                    int i;
                    gchar **parts = g_strsplit(s, ",", 0);

                    for (i = 0; parts[i]; i++) {
                        gchar *ip = parts[i];
                        while (*ip == ' ')
                            ip++;

                        in_addr_t ia = inet_addr(ip);
                        if (ia == 0 || ia == 0xffffffff) {
                            moloch_session_add_tag(session, "http:bad-xff");
                            LOG("ERROR - Didn't understand ip: %s %s %d",
                                http->save_header[which].hdr[i]->value, ip, ia);
                            continue;
                        }

                        moloch_field_int_add(pos, session, ia);
                    }

                    g_strfreev(parts);
                    break;
                }
        } /* SWITCH */
    }
}
/******************************************************************************/
void http_make_pos(HTTPInfo_t *http)
{
    int which = http->which;
    char                   header[200];
    MolochString_t        *hstring = 0;
    size_t i;

    for (i = 0; i < http->phr_headers_num[which]; i++) {
        if (http->phr_headers[which][i].name == NULL) continue;

        char *lower = g_ascii_strdown(http->phr_headers[which][i].name, http->phr_headers[which][i].name_len);
        if (which == http->reqWhich)
            HASH_FIND(s_, httpReqHeaders, lower, hstring);
        else
            HASH_FIND(s_, httpResHeaders, lower, hstring);

        if (hstring)
        {
            if (http->save_headers_num[which] < MAX_HTTP_HEADERS) {
                http->save_header[which].hdr[http->save_headers_num[which]] = &http->phr_headers[which][i];
                http->save_header[which].pos[http->save_headers_num[which]] = (long)hstring->uw;

                snprintf(header, sizeof(header), "http:header:%s", lower);

                http->save_headers_num[which]++;

                if (which)
                    moloch_session_add_tag_type(http->session, tagsResField, header);
                else
                    moloch_session_add_tag_type(http->session, tagsReqField, header);
            }
        }

        if (strcmp("host", lower) == 0) {
            http->hostString = g_string_new_len("//", 2);
            g_string_append_len(http->hostString, http->phr_headers[which][i].value,
                    http->phr_headers[which][i].value_len);
            strcpy(http->zmqdata.host, http->hostString->str + 2);
        } else if (strcmp("content-range", lower) == 0) {
            http->rangeString = g_string_new_len("", 0);
            g_string_append_len(http->rangeString, http->phr_headers[which][i].value,
                    http->phr_headers[which][i].value_len);
            strcpy(http->zmqdata.range, http->rangeString->str + strlen("bytes"));
        } else if (strcmp("cookie", lower) == 0) {
            http->cookieString = g_string_new_len(http->phr_headers[which][i].value,
                    http->phr_headers[which][i].value_len);
        } else if (strcmp("authorization", lower) == 0) {
            http->authString = g_string_new_len(http->phr_headers[which][i].value,
                    http->phr_headers[which][i].value_len);
        } else if (strcmp("content-length", lower) == 0) {
            char strContentLen[1024];
            strncpy(strContentLen, http->phr_headers[which][i].value, http->phr_headers[which][i].value_len);
            strContentLen[http->phr_headers[which][i].value_len] = '\0';
            http->content_len = atoi(strContentLen);
            http->zmqdata.filesize = atoi(strContentLen);
        } else if (strcmp("content-type", lower) == 0) {
            http->contentTypeString = g_string_new_len("", 0);
            g_string_append_len(http->contentTypeString, http->phr_headers[which][i].value,
                    http->phr_headers[which][i].value_len);
            char *strContentType = http->contentTypeString->str;
            if (strstr(strContentType, "multipart") == strContentType) {
                http->is_multipart = 1;
            }
            strcpy(http->zmqdata.content_type, strContentType);
        }

        g_free(lower);
    }
}

int
http_parse_success(HTTPInfo_t *http)
{
    MolochSession_t       *session = http->session;
    char                   version[20];
    int         which = http->which;


#ifdef HTTPDEBUG
    LOG("HTTPDEBUG: which: %d code: %d method: %d", http->which, parser->status_code, parser->method);
#endif

    //request http version
    int len = snprintf(version, sizeof(version), "1.%d", http->minor_version[which]);

    //request
    if (which == http->reqWhich) {
        moloch_field_string_add(methodField, session, http->method_p, http->method_len, TRUE);
        moloch_field_string_add(verReqField, session, version, len, TRUE);
        http->urlString = g_string_new_len(http->url_p, http->url_len);
        if (http->url_len >= URL_LEN - 1) {
            strncpy(http->zmqdata.uri, http->url_p, URL_LEN - 1);
            http->zmqdata.uri[URL_LEN] = '\0';
        }
        else {
            strncpy(http->zmqdata.uri, http->url_p, http->url_len);
            http->zmqdata.uri[http->url_len] = '\0';
        }
    }
    //response
    else {
        moloch_field_int_add(statuscodeField, session, http->status_code);
        moloch_field_string_add(verResField, session, version, len, TRUE);
    }

    http_add_value(session, http);

    if (http->urlString) {
        char *ch = http->urlString->str;
        while (*ch) {
            if (*ch < 32) {
                moloch_session_add_tag(session, "http:control-char");
                break;
            }
            ch++;
        }
    }

    if (http->cookieString && http->cookieString->str[0]) {
        char *start = http->cookieString->str;
        while (1) {
            while (isspace(*start)) start++;
            char *equal = strchr(start, '=');
            if (!equal)
                break;
            moloch_field_string_add(cookieKeyField, session, start, equal-start, TRUE);
            start = strchr(equal+1, ';');
            if (config.parseCookieValue) {
                equal++;
                while (isspace(*equal)) equal++;
                if (*equal && equal != start)
                    moloch_field_string_add(cookieValueField, session, equal, start?start-equal:-1, TRUE);
            }

            if(!start)
                break;
            start++;
        }
        g_string_truncate(http->cookieString, 0);
    }

    if (http->authString && http->authString->str[0]) {
        moloch_http_parse_authorization(session, http->authString->str);
        g_string_truncate(http->authString, 0);
    }

    if (http->hostString) {
        g_string_ascii_down(http->hostString);
    }

    gboolean truncated = FALSE;
    if (http->urlString && http->hostString) {
        char *colon = strchr(http->hostString->str+2, ':');
        if (colon) {
            moloch_field_string_add(hostField, session, http->hostString->str+2, colon - http->hostString->str-2, TRUE);
        } else {
            moloch_field_string_add(hostField, session, http->hostString->str+2, http->hostString->len-2, TRUE);
        }

        char *question = strchr(http->urlString->str, '?');
        if (question) {
            moloch_field_string_add(pathField, session, http->urlString->str, question - http->urlString->str, TRUE);
            char *start = question+1;
            char *ch;
            int   field = keyField;
            for (ch = start; *ch; ch++) {
                if (*ch == '&') {
                    if (ch != start && (config.parseQSValue || field == keyField)) {
                        char *str = g_uri_unescape_segment(start, ch, NULL);
                        if (!str) {
                            moloch_field_string_add(field, session, start, ch-start, TRUE);
                        } else if (!moloch_field_string_add(field, session, str, -1, FALSE)) {
                            g_free(str);
                        }
                    }
                    start = ch+1;
                    field = keyField;
                    continue;
                } else if (*ch == '=') {
                    if (ch != start && (config.parseQSValue || field == keyField)) {
                        char *str = g_uri_unescape_segment(start, ch, NULL);
                        if (!str) {
                            moloch_field_string_add(field, session, start, ch-start, TRUE);
                        } else if (!moloch_field_string_add(field, session, str, -1, FALSE)) {
                            g_free(str);
                        }
                    }
                    start = ch+1;
                    field = valueField;
                }
            }
            if (config.parseQSValue && field == valueField && ch > start) {
                char *str = g_uri_unescape_segment(start, ch, NULL);
                if (!str) {
                    moloch_field_string_add(field, session, start, ch-start, TRUE);
                } else if (!moloch_field_string_add(field, session, str, -1, FALSE)) {
                    g_free(str);
                }
            }
        } else {
            moloch_field_string_add(pathField, session, http->urlString->str, http->urlString->len, TRUE);
        }

        if (http->urlString->str[0] != '/') {
            char *result = strstr(http->urlString->str, http->hostString->str+2);

            /* If the host header is in the first 8 bytes of url then just use the url */
            if (result && result - http->urlString->str <= 8) {
                moloch_field_string_add(urlsField, session, http->urlString->str, MIN(MAX_URL_LENGTH, http->urlString->len), FALSE);
                truncated = http->urlString->len > MAX_URL_LENGTH;
                g_string_free(http->urlString, FALSE);
                g_string_free(http->hostString, TRUE);
            } else {
                /* Host header doesn't match the url */
                g_string_append(http->hostString, ";");
                g_string_append(http->hostString, http->urlString->str);
                moloch_field_string_add(urlsField, session, http->hostString->str, MIN(MAX_URL_LENGTH, http->hostString->len), FALSE);
                truncated = http->hostString->len > MAX_URL_LENGTH;
                g_string_free(http->urlString, TRUE);
                g_string_free(http->hostString, FALSE);
            }
        } else {
            /* Normal case, url starts with /, so no extra host in url */
            g_string_append(http->hostString, http->urlString->str);
            moloch_field_string_add(urlsField, session, http->hostString->str, MIN(MAX_URL_LENGTH, http->hostString->len), FALSE);
            truncated = http->hostString->len > MAX_URL_LENGTH;
            g_string_free(http->urlString, TRUE);
            g_string_free(http->hostString, FALSE);
        }

        http->urlString = NULL;
        http->hostString = NULL;
    } else if (http->urlString) {
        moloch_field_string_add(urlsField, session, http->urlString->str, MIN(MAX_URL_LENGTH, http->urlString->len), FALSE);
        truncated = http->urlString->len > MAX_URL_LENGTH;
        g_string_free(http->urlString, FALSE);


        http->urlString = NULL;
    } else if (http->hostString) {
        char *colon = strchr(http->hostString->str+2, ':');
        if (colon) {
            moloch_field_string_add(hostField, session, http->hostString->str+2, colon - http->hostString->str-2, TRUE);
        } else {
            moloch_field_string_add(hostField, session, http->hostString->str+2, http->hostString->len-2, TRUE);
        }

        g_string_free(http->hostString, TRUE);
        http->hostString = NULL;
    }

    if (truncated)
        moloch_session_add_tag(session, "http:url-truncated");

    moloch_session_add_protocol(session, "http");

    return 0;
}

/*############################## SHARED ##############################*/
/******************************************************************************/
int http_parse(MolochSession_t *UNUSED(session), void *uw, const unsigned char *data, int remaining, int which)
{
    HTTPInfo_t            *http          = uw;

    http->which = which;
#ifdef HTTPDEBUG
    LOG("HTTPDEBUG: enter %d - %d %.*s", http->which, remaining, remaining, data);
#endif

    int ret;
    const char *req_data;
    int req_len;

    http->phr_headers_num[which] = MAX_HTTP_HEADERS;

    if (http->pkt_buffer[which]) {
        g_string_append_len(http->pkt_buffer[which], (const gchar *)data, remaining);
        req_data = (const char *)http->pkt_buffer[which]->str;
        req_len = http->pkt_buffer[which]->len;
    }
    else {
        req_data = (const char *)data;
        req_len = remaining;
    }

    if ((http->wParsers & (1 << http->which)) == 0) {
        _process_http_payload(http, req_data, req_len);
        return 0;
    }

    //printf("phr_parse check which : %d, reqWhich : %d\n", which, http->reqWhich);

    if (which == http->reqWhich) {
    ret = phr_parse_request(req_data, req_len,
            &http->method_p, &http->method_len,
            &http->url_p, &http->url_len,
            &http->minor_version[which],
            http->phr_headers[which],
            &http->phr_headers_num[which],
            0);
    }
    else {
    ret = phr_parse_response(req_data, req_len,
            &http->minor_version[which],
            &http->status_code,
            &http->msg,
            &http->msg_len,
            http->phr_headers[which],
            &http->phr_headers_num[which],
            0);
    }

#if 0
    uint32_t addr1 = ((uint32_t *)session->addr1.s6_addr)[3];
    uint32_t addr2 = ((uint32_t *)session->addr2.s6_addr)[3];
    printf("%ld.%ld %u.%u.%u.%u(%u)->%u.%u.%u.%u(%u), %p\n",
            session->firstPacket.tv_sec,
            session->firstPacket.tv_usec,
            ((uint8_t *)&addr1)[0],
            ((uint8_t *)&addr1)[1],
            ((uint8_t *)&addr1)[2],
            ((uint8_t *)&addr1)[3],
            session->port1,
            ((uint8_t *)&addr2)[0],
            ((uint8_t *)&addr2)[1],
            ((uint8_t *)&addr2)[2],
            ((uint8_t *)&addr2)[3],
            session->port2, session);
    printf("req_data : %.*s\n", req_len, req_data);
#endif

    //cannot parse header
    if (ret == -1) {
/*
        printf("phr_parse_%s failed, %d, %p\n", which != http->reqWhich ?"response":"request", ret, session);
        printf("minor_version : %d, status_code : %d\n", http->minor_version[which], http->status_code);
        printf("phr_headers_num : %ld\n", http->phr_headers_num[which]);
        printf("%.*s\n", req_len, req_data);
*/

        if (http->pkt_buffer[which]) {
            g_string_free(http->pkt_buffer[which], TRUE);
            http->pkt_buffer[which] = NULL;
        }
    }
    //not complete for parse header
    else if (ret == -2) {
        if (http->pkt_buffer[which] == NULL) {
            //printf("pkt_buffering start in %s, %p\n", which != http->reqWhich ?"response":"request", session);
            http->pkt_buffer[which] = g_string_new_len((const gchar *)req_data, req_len);
        }
        //else printf("already buffered http_data : %d\n", http->pkt_buffer[which]->len);
    }
    //success
    else {
        http->inHeader |= (1 << http->which);
        http->wParsers &= ~(1 << http->which);

        http_make_pos(http);
        http_parse_success(http);
        if (http->content_len > 0) {
            if (!http->is_multipart) {
                char filepath[1024];
                sprintf(filepath, "%s/%s", config.fileExtractDir, http->which ? "http_res_file" : "http_req_file");
                char uniq_name[1024] = "";
                cm_get_uniq_name(filepath, uniq_name);
                fm_open(http->fm[http->which], uniq_name, http->content_len);
                fm_add_cb(http->fm[http->which], _http_extract, http);
                sprintf(http->zmqdata.filepath, "%s/%s", ROOTPATH, uniq_name);
            }
            else {
                char boundary[1024] = "";
                char *bnd;
                char *tag = "boundary=";
                if ((bnd = strstr(http->contentTypeString->str, tag))) {
                    boundary[0] = '-';
                    boundary[1] = '-';
                    strcpy(boundary + 2, bnd + strlen(tag));
                }
                http->parser = multipart_parser_init(boundary, &(http->callbacks));
                multipart_parser_set_data(http->parser, http);
            }
        }
        if (http->rangeString) {
            fm_add_cb(http->fm[http->which], _partial_file_complete, http);
        }
        if (req_len - ret > 0) {
            _process_http_payload(http, req_data + ret, req_len - ret);
        }
        //printf("phr_parse_%s success, %p\n", which != http->reqWhich ?"response":"request", session);
        if (http->pkt_buffer[which]) {
            g_string_free(http->pkt_buffer[which], TRUE);
            http->pkt_buffer[which] = NULL;
        }
    }
    fingerprint_http(session, http->phr_headers[which], http->phr_headers_num[which], http->reqWhich == which, http->minor_version[which]);

    return 0;
}

void _partial_file_complete(void *data)
{
    printf("Partial file completed");
    zmqdata_t *zmqdata = &((HTTPInfo_t *)data)->zmqdata;
#ifdef TESTMODE
    printf("Send to mfile %s\n", zmqdata->filepath);
    printf("Url %s\n", zmqdata->uri);
    printf("Host %s\n", zmqdata->host);
    printf("Range %s\n", zmqdata->range);
    printf("Filepath %s\n", zmqdata->filepath);
    printf("Filesize %lu\n", zmqdata->filesize);
    printf("Content type %s\n", zmqdata->content_type);
    fflush(stdout);
#else
    printf("Send to mfile %s\n", zmqdata->filepath);
    void *context = NULL;
    void *socket = NULL;
    if (!context) {
        context = zmq_ctx_new();
        socket = zmq_socket(context, ZMQ_REQ);
        int rc = zmq_connect(socket, zmq_url);
    }

    zmq_msg_t msg;
    int ret;
    zmq_msg_init_data(&msg, zmqdata, sizeof(*zmqdata), NULL, NULL);
    zmq_msg_send(&msg, socket, 0);
    zmq_recv(socket, &ret, sizeof(int), 0);
#endif
}

static void _http_extract(void *data)
{
    HTTPInfo_t *http = (HTTPInfo_t *)data;
    MolochExtractFile_t info;
    char buf[1000];
    sprintf(info.id, "%s-%d", moloch_session_id_string(http->session->sessionId, buf), http->filecount++);
    strcpy(info.type, "http");
    info.time=0;
    info.times=http->session->lastPacket.tv_sec;
    info.timeu=http->session->lastPacket.tv_usec;
    info.a1 = 0;
    info.a2 = 0;
    info.p1=http->session->port1;
    info.p2=http->session->port2;
    info.thread = http->session->thread;
    strcpy(info.method, "TEST");
    strcpy(info.host, http->zmqdata.host);
    strcpy(info.cont_type, http->zmqdata.content_type);
    strcpy(info.path, http->zmqdata.filepath);
    moloch_db_save_file_extract(&info);
    char *attachid = strdup(info.id);
    moloch_field_string_add(attachIdField, http->session, attachid, -1, FALSE);
}

/******************************************************************************/
void http_free(MolochSession_t UNUSED(*session), void *uw)
{
    HTTPInfo_t            *http          = uw;

    if (http->urlString)
        g_string_free(http->urlString, TRUE);
    if (http->hostString)
        g_string_free(http->hostString, TRUE);
    if (http->rangeString)
        g_string_free(http->rangeString, TRUE);
    if (http->cookieString)
        g_string_free(http->cookieString, TRUE);
    if (http->authString)
        g_string_free(http->authString, TRUE);
    fm_free(http->fm[0]);
    fm_free(http->fm[1]);
    if (http->pkt_buffer[0])
    g_string_free(http->pkt_buffer[0], TRUE);

    if (http->pkt_buffer[1])
    g_string_free(http->pkt_buffer[1], TRUE);
    multipart_parser_free(http->parser);

    MOLOCH_TYPE_FREE(HTTPInfo_t, http);
}
/******************************************************************************/
//void http_classify(MolochSession_t *session, const unsigned char *UNUSED(data), int UNUSED(len), int UNUSED(which))
void http_classify(MolochSession_t *session, const unsigned char *UNUSED(data), int UNUSED(len), int which, void *UNUSED(uw))
{
    if (moloch_session_has_protocol(session, "http"))
        return;

    moloch_session_add_protocol(session, "http");

    HTTPInfo_t            *http          = MOLOCH_TYPE_ALLOC0(HTTPInfo_t);

    //http->checksum[0] = g_checksum_new(G_CHECKSUM_MD5);
    //http->checksum[1] = g_checksum_new(G_CHECKSUM_MD5);

    http->wParsers = 3;
    http->session = session;
    http->reqWhich = which;
    http->callbacks.on_part_data = _on_part_data;
    http->callbacks.on_part_data_begin = _on_part_data_begin;
    http->callbacks.on_part_data_end = _on_part_data_end;
    http->fm[0] = fm_init();
    http->fm[1] = fm_init();
    moloch_parsers_register(session, http_parse, http, http_free);
}
/******************************************************************************/
void moloch_parser_init()
{
static const char *method_strings[] =
    {
#define XX(num, name, string) #string,
    HTTP_METHOD_MAP(XX)
#undef XX
    0
    };

    hostField = moloch_field_define("http", "lotermfield",
        "host.http", "Hostname", "ho",
        "HTTP host header field",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "aliases", "[\"http.host\"]",
        "category", "host",
        NULL);

    urlsField = moloch_field_define("http", "textfield",
        "http.uri", "URI", "us",
        "URIs for request",
        MOLOCH_FIELD_TYPE_STR_ARRAY, MOLOCH_FIELD_FLAG_CNT,
        "rawField", "rawus",
        "category", "[\"url\",\"host\"]",
        NULL);

    xffField = moloch_field_define("http", "ip",
        "ip.xff", "XFF IP", "xff",
        "X-Forwarded-For Header",
        MOLOCH_FIELD_TYPE_IP_GHASH, MOLOCH_FIELD_FLAG_SCNT | MOLOCH_FIELD_FLAG_IPPRE,
        "category", "ip",
        NULL);

    uaField = moloch_field_define("http", "textfield",
        "http.user-agent", "Useragent", "ua",
        "User-Agent Header",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "rawField", "rawua",
        NULL);

    tagsReqField = moloch_field_define("http", "lotermfield",
        "http.hasheader.src", "Has Src Header", "hh1",
        "Request has header present",
        MOLOCH_FIELD_TYPE_INT_GHASH,  MOLOCH_FIELD_FLAG_CNT,
        NULL);

    tagsResField = moloch_field_define("http", "lotermfield",
        "http.hasheader.dst", "Has Dst Header", "hh2",
        "Response has header present",
        MOLOCH_FIELD_TYPE_INT_GHASH,  MOLOCH_FIELD_FLAG_CNT,
        NULL);

    moloch_field_define("http", "lotermfield",
        "http.hasheader", "Has Src or Dst Header", "hhall",
        "Shorthand for http.hasheader.src or http.hasheader.dst",
        0,  MOLOCH_FIELD_FLAG_FAKE,
        "regex", "^http.hasheader\\\\.(?:(?!\\\\.cnt$).)*$",
        NULL);

/*
    md5Field = moloch_field_define("http", "lotermfield",
        "http.md5", "Body MD5", "hmd5",
        "MD5 of http body response",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "category", "md5",
        NULL);
*/

    moloch_field_define("http", "termfield",
        "http.version", "Version", "httpversion",
        "HTTP version number",
        0, MOLOCH_FIELD_FLAG_FAKE,
        "regex", "^http.version.[a-z]+$",
        NULL);

    verReqField = moloch_field_define("http", "termfield",
        "http.version.src", "Src Version", "hsver",
        "Request HTTP version number",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        NULL);

    verResField = moloch_field_define("http", "termfield",
        "http.version.dst", "Dst Version", "hdver",
        "Response HTTP version number",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        NULL);

    pathField = moloch_field_define("http", "termfield",
        "http.uri.path", "URI Path", "hpath",
        "Path portion of URI",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        NULL);

    keyField = moloch_field_define("http", "termfield",
        "http.uri.key", "QS Keys", "hkey",
        "Keys from query string of URI",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        NULL);

    valueField = moloch_field_define("http", "termfield",
        "http.uri.value", "QS Values", "hval",
        "Values from query string of URI",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        NULL);

    cookieKeyField = moloch_field_define("http", "termfield",
        "http.cookie.key", "Cookie Keys", "hckey-term",
        "The keys to cookies sent up in requests",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_COUNT,
        NULL);

    cookieValueField = moloch_field_define("http", "termfield",
        "http.cookie.value", "Cookie Values", "hcval-term",
        "The values to cookies sent up in requests",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_COUNT,
        NULL);

    methodField = moloch_field_define("http", "termfield",
        "http.method", "Request Method", "http.method-term",
        "HTTP Request Method",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_COUNT,
        NULL);

/*
    magicField = moloch_field_define("http", "termfield",
        "http.bodymagic", "Body Magic", "http.bodymagic-term",
        "The content type of body determined by libfile/magic",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_COUNT,
        NULL);
*/

    userField = moloch_field_define("http", "termfield",
        "http.user", "User", "huser-term",
        "HTTP Auth User",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "category", "user",
        NULL);

    atField = moloch_field_define("http", "lotermfield",
        "http.authtype", "Auth Type", "hat-term",
        "HTTP Auth Type",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        NULL);

    attachIdField = moloch_field_define("http", "termfield",
        "http.attach", "Filenames", "eattach",
        "HTTP attachment id",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "attach",
        NULL);
    statuscodeField = moloch_field_define("http", "integer",
        "http.statuscode", "Status Code", "http.statuscode",
        "Response HTTP numeric status code",
        MOLOCH_FIELD_TYPE_INT_GHASH,  MOLOCH_FIELD_FLAG_COUNT,
        NULL);

    HASH_INIT(s_, httpReqHeaders, moloch_string_hash, moloch_string_cmp);
    HASH_INIT(s_, httpResHeaders, moloch_string_hash, moloch_string_cmp);

    moloch_config_add_header(&httpReqHeaders, "x-forwarded-for", xffField);
    moloch_config_add_header(&httpReqHeaders, "user-agent", uaField);
    moloch_config_add_header(&httpReqHeaders, "host", hostField);
    moloch_config_load_header("headers-http-request", "http", "Request header ", "http.", "hdrs.hreq-", &httpReqHeaders, 0);
    moloch_config_load_header("headers-http-response", "http", "Response header ", "http.", "hdrs.hres-", &httpResHeaders, 0);

    int i;
    for (i = 0; method_strings[i]; i++) {
        moloch_parsers_classifier_register_tcp("http", NULL, 0, (unsigned char*)method_strings[i], strlen(method_strings[i]), http_classify);
    }

    memset(&parserSettings, 0, sizeof(parserSettings));
/*
    parserSettings.on_message_begin = moloch_hp_cb_on_message_begin;
    parserSettings.on_url = moloch_hp_cb_on_url;
    parserSettings.on_body = moloch_hp_cb_on_body;
    parserSettings.on_headers_complete = moloch_hp_cb_on_headers_complete;
    parserSettings.on_message_complete = moloch_hp_cb_on_message_complete;
    parserSettings.on_header_field = moloch_hp_cb_on_header_field;
    parserSettings.on_header_value = moloch_hp_cb_on_header_value;
*/
}

int _on_part_data_begin(multipart_parser *p)
{
    HTTPInfo_t *http = (HTTPInfo_t *)multipart_parser_get_data(p);
    char filepath[1024];
    char uniq_name[1024];

    sprintf(filepath, "%s/%s", config.fileExtractDir, "multipart");
    cm_get_uniq_name(filepath, uniq_name);
    fm_open(http->fm[http->which], uniq_name, 0);
    fm_add_cb(http->fm[0], _http_extract, http);
    return 0;
}

int _on_part_data(multipart_parser *p, const char *at, size_t length)
{
    HTTPInfo_t *http = (HTTPInfo_t *)multipart_parser_get_data(p);
    if ( length > 0) {
        fm_write(http->fm[http->which], at, length);
    }
    return 0;
}

int _on_part_data_end(multipart_parser *p)
{
    HTTPInfo_t *http = (HTTPInfo_t *)multipart_parser_get_data(p);
    fm_close(http->fm[http->which]);
    http->is_multipart = 0;
    http->wParsers = 3;
    return 0;
}

void _process_http_payload(HTTPInfo_t *http, const char *buff, size_t buflen)
{
    if (!http->is_multipart) {
        int file_completed = fm_write(http->fm[http->which], buff, buflen);
        if (file_completed) http->wParsers = 3;
    }
    else {
        multipart_parser_execute(http->parser, buff, buflen);
    }
}
