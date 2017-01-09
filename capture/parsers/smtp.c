/* Copyright 2012-2016 AOL Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this Software except in compliance with the License.
 * You may obtain a copy of the License at
 *
t
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
#include <ripmime-api.h>
#include <mime.h>
#include "file_manager.h"
#include "common.h"
#include "email_util.h"

//#define EMAILDEBUG

extern MolochConfig_t   config;
extern char            *moloch_char_to_hex;
extern unsigned char    moloch_char_to_hexstr[256][3];
extern uint32_t         pluginsCbs;

static MolochStringHashStd_t emailHeaders;

static int receivedField;
static int idField;
static int ipField;
static int hostField;
static int srcField;
static int dstField;
extern int userField;
static int hhField;
static int subField;
static int ctField;
static int md5Field;
static int fnField;
static int uaField;
static int mvField;
static int fctField;
static int magicField;
static int attachIdField;

typedef struct {
    MolochStringHead_t boundaries;
    char               state[2];
    char               needStatus[2];
    GString           *line[2];
    gint               state64[2];
    guint              save64[2];
    GChecksum         *checksum[2];
    fm_t               *fm;
    MolochSession_t    *session;
    char               *eml_path;

    uint16_t           base64Decode:2;
    uint16_t           firstInContent:2;
    int                filecount;
} SMTPInfo_t;

/******************************************************************************/
enum {
EMAIL_CMD,
EMAIL_CMD_RETURN,

EMAIL_AUTHLOGIN,
EMAIL_AUTHLOGIN_RETURN,

EMAIL_AUTHPLAIN,
EMAIL_AUTHPLAIN_RETURN,
EMAIL_DATA_HEADER,
EMAIL_DATA_HEADER_RETURN,
EMAIL_DATA_HEADER_DONE,
EMAIL_DATA,
EMAIL_DATA_RETURN,
EMAIL_IGNORE,
EMAIL_TLS_OK,
EMAIL_TLS_OK_RETURN,
EMAIL_TLS,
EMAIL_MIME,
EMAIL_MIME_RETURN,
EMAIL_MIME_DONE,
EMAIL_MIME_DATA,
EMAIL_MIME_DATA_RETURN
};

static void _extract_eml(void *data);
static void _save_file_meta(SMTPInfo_t *smtp, struct email_attach_file *file);

/******************************************************************************/
int smtp_parser(MolochSession_t *session, void *uw, const unsigned char *data, int remaining, int which)
{
    SMTPInfo_t           *email        = uw;
    GString              *line         = email->line[which];
    char                 *state        = &email->state[which];
    MolochString_t       *emailHeader  = 0;
    char filepath[1024];

#ifdef EMAILDEBUG
    LOG("EMAILDEBUG: enter %d %d %d %.*s", which, *state, email->needStatus[(which + 1) % 2], remaining, data);
#endif

    if (*state == EMAIL_DATA_HEADER || *state == EMAIL_DATA || *state == EMAIL_MIME_DATA) {
        fm_write(email->fm, (const char *)data, remaining);
    }
    while (remaining > 0) {
        switch (*state) {
        case EMAIL_AUTHPLAIN:
        case EMAIL_AUTHLOGIN:
        case EMAIL_CMD: {
            if (*data == '\r') {
                (*state)++;
                break;
            }
            g_string_append_c(line, *data);
            break;
        }
        case EMAIL_CMD_RETURN: {
#ifdef EMAILDEBUG
            printf("%d %d cmd => %s\n", which, *state, line->str);
#endif
            if (email->needStatus[(which + 1) % 2]) {
                email->needStatus[(which + 1) % 2] = 0;
                char tag[200];
                snprintf(tag, sizeof(tag), "smtp:statuscode:%d", atoi(line->str));
                moloch_session_add_tag(session, tag);
            } else if (strncasecmp(line->str, "MAIL FROM:", 10) == 0) {
                *state = EMAIL_CMD;
                char *lower = g_ascii_strdown(email_remove_matching(line->str+10, '<', '>'), -1);
                if (!moloch_field_string_add(srcField, session, lower, -1, FALSE)) {
                    g_free(lower);
                }
            } else if (strncasecmp(line->str, "RCPT TO:", 8) == 0) {
                char *lower = g_ascii_strdown(email_remove_matching(line->str+8, '<', '>'), -1);
                if (!moloch_field_string_add(dstField, session, lower, -1, FALSE)) {
                    g_free(lower);
                }
                *state = EMAIL_CMD;
            } else if (strncasecmp(line->str, "DATA", 4) == 0) {
                *state = EMAIL_DATA_HEADER;
                email->eml_path = (char *)malloc(sizeof(char) * 1024);
                sprintf(filepath, "%s/smtp_eml_%ld", config.fileExtractDir, time(NULL));
                cm_get_uniq_name(filepath, email->eml_path);
                fm_open(email->fm, email->eml_path, 1000000);
                if (config.emlExtract) {
                    fm_add_cb(email->fm, _extract_eml, email);
                }
            } else if (strncasecmp(line->str, "AUTH LOGIN", 10) == 0) {
                moloch_session_add_tag(session, "smtp:authlogin");
                if (line->len > 11) {
                    gsize out_len = 0;
                    g_base64_decode_inplace(line->str+11, &out_len);
                    if (out_len > 0) {
                        moloch_field_string_add(userField, session, line->str+11, out_len, TRUE);
                    }
                    *state = EMAIL_CMD;
                } else {
                    *state = EMAIL_AUTHLOGIN;
                }
            } else if (strncasecmp(line->str, "AUTH PLAIN", 10) == 0) {
                moloch_session_add_tag(session, "smtp:authplain");
                if (line->len > 11) {
                    gsize out_len = 0;
                    gsize zation = 0;
                    gsize cation = 0;
                    g_base64_decode_inplace(line->str+11, &out_len);
                    zation = strlen(line->str+11);
                    if (zation < out_len) {
                        cation = strlen(line->str+11+zation+1);
                        if (cation+zation+1 < out_len) {
                            moloch_field_string_add(userField, session, line->str+11+zation+1, cation, TRUE);
                        }
                    }
                    *state = EMAIL_CMD;
                } else {
                    *state = EMAIL_AUTHPLAIN;
                }
            } else if (strncasecmp(line->str, "STARTTLS", 8) == 0) {
                moloch_session_add_tag(session, "smtp:starttls");
                *state = EMAIL_IGNORE;
                email->state[(which+1)%2] = EMAIL_TLS_OK;
                return 0;
            } else {
                *state = EMAIL_CMD;
            }

            g_string_truncate(line, 0);
            if (*data != '\n')
                continue;
            break;
        }
        case EMAIL_AUTHLOGIN_RETURN: {
            gsize out_len = 0;
            g_base64_decode_inplace(line->str, &out_len);
            if (out_len > 0) {
                moloch_field_string_add(userField, session, line->str, out_len, TRUE);
            }
            *state = EMAIL_CMD;
            break;
        }
        case EMAIL_AUTHPLAIN_RETURN: {
            gsize out_len = 0;
            gsize zation = 0;
            gsize cation = 0;
            g_base64_decode_inplace(line->str, &out_len);
            zation = strlen(line->str);
            if (zation < out_len) {
                cation = strlen(line->str+zation+1);
                if (cation+zation+1 < out_len) {
                    moloch_field_string_add(userField, session, line->str+zation+1, cation, TRUE);
                }
            }
            *state = EMAIL_CMD;
            break;
        }
        case EMAIL_DATA_HEADER: {
            if (*data == '\r') {
                *state = EMAIL_DATA_HEADER_RETURN;
                break;
            }
            g_string_append_c(line, *data);
            break;
        }
        case EMAIL_DATA_HEADER_RETURN: {
#ifdef EMAILDEBUG
            printf("%d %d header => %s\n", which, *state, line->str);
#endif
            if (strcmp(line->str, ".") == 0) {
                email->needStatus[which] = 1;
                *state = EMAIL_CMD;
            } else if (*line->str == 0) {
                *state = EMAIL_DATA;
                if (pluginsCbs & MOLOCH_PLUGIN_SMTP_OHC) {
                    moloch_plugins_cb_smtp_ohc(session);
                }
            } else {
                *state = EMAIL_DATA_HEADER_DONE;
            }

            if (*data != '\n')
                continue;
            break;
        }
        case EMAIL_DATA_HEADER_DONE: {
#ifdef EMAILDEBUG
            printf("%d %d header done => %s (%c)\n", which, *state, line->str, *data);
#endif
            *state = EMAIL_DATA_HEADER;

            if (*data == ' ' || *data == '\t') {
                g_string_append_c(line, ' ');
                break;
            }

            char *colon = strchr(line->str, ':');
            if (!colon) {
                g_string_truncate(line, 0);
                break;
            }

            char *lower = g_ascii_strdown(line->str, colon - line->str);
            HASH_FIND(s_, emailHeaders, lower, emailHeader);

            moloch_field_string_add(hhField, session, lower, colon - line->str, TRUE);

            if (emailHeader) {
                int cpos = colon - line->str + 1;

                if ((long)emailHeader->uw == subField) {
                    if (line->str[8] != ' ') {
                        moloch_session_add_tag(session, "smtp:missing-subject-space");
                        email_add_encoded(session, subField, line->str+8, line->len-8);
                    } else {
                        email_add_encoded(session, subField, line->str+9, line->len-9);
                    }
                } else if ((long)emailHeader->uw == dstField) {
                    email_parse_addresses(dstField, session, line->str+cpos, line->len-cpos);
                } else if ((long)emailHeader->uw == srcField) {
                    email_parse_addresses(srcField, session, line->str+cpos, line->len-cpos);
                } else if ((long)emailHeader->uw == idField) {
                    moloch_field_string_add(idField, session, email_remove_matching(line->str+cpos, '<', '>'), -1, TRUE);
                } else if ((long)emailHeader->uw == receivedField) {
                    email_parse_received(session, line->str+cpos, line->len-cpos, ipField, hostField);
                } else if ((long)emailHeader->uw == ctField) {
                    char *s = line->str + 13;
                    while(isspace(*s)) s++;

                    moloch_field_string_add(ctField, session, s, -1, TRUE);
                    char *boundary = (char *)moloch_memcasestr(s, line->len - (s - line->str), "boundary=", 9);
                    if (boundary) {
                        MolochString_t *string = MOLOCH_TYPE_ALLOC0(MolochString_t);
                        string->str = g_strdup(email_remove_matching(boundary+9, '"', '"'));
                        string->len = strlen(string->str);
                        DLL_PUSH_TAIL(s_, &email->boundaries, string);
                    }
                } else {
                    email_add_value(session, (long)emailHeader->uw, line->str + cpos , line->len - cpos);
                }
            } else {
                int i;
                for (i = 0; config.smtpIpHeaders && config.smtpIpHeaders[i]; i++) {
                    if (strcasecmp(lower, config.smtpIpHeaders[i]) == 0) {
                        int l = strlen(config.smtpIpHeaders[i]);
                        char *ip = email_remove_matching(line->str+l+1, '[', ']');
                        in_addr_t ia = inet_addr(ip);
                        if (ia == 0 || ia == 0xffffffff)
                            break;
                        moloch_field_int_add(ipField, session, ia);
                    }
                }
            }

            if (pluginsCbs & MOLOCH_PLUGIN_SMTP_OH) {
                moloch_plugins_cb_smtp_oh(session, lower, colon - line->str, colon + 1, line->len - (colon - line->str) - 1);
            }

            g_free(lower);

            g_string_truncate(line, 0);
            if (*data != '\n')
                continue;
            break;
        }
        case EMAIL_MIME_DATA:
        case EMAIL_DATA: {
            if (*data == '\r') {
                (*state)++;
                break;
            }
            g_string_append_c(line, *data);
            break;
        }
        case EMAIL_MIME_DATA_RETURN:
        case EMAIL_DATA_RETURN: {
#ifdef EMAILDEBUG
            printf("%d %d %sdata => %s\n", which, *state, (*state == EMAIL_MIME_DATA_RETURN?"mime ": ""), line->str);
#endif
            if (strcmp(line->str, ".") == 0) {
                email->needStatus[which] = 1;
                *state = EMAIL_CMD;
                fm_close(email->fm);
            } else {
                MolochString_t *string;
                gboolean        found = FALSE;

                if (line->str[0] == '-') {
                    DLL_FOREACH(s_,&email->boundaries,string) {
                        if ((int)line->len >= (int)(string->len + 2) && memcmp(line->str+2, string->str, string->len) == 0) {
                            found = TRUE;
                            break;
                        }
                    }
                }

                if (found) {
                    if (email->base64Decode & (1 << which)) {
                        const char *md5 = g_checksum_get_string(email->checksum[which]);
                        moloch_field_string_add(md5Field, session, (char*)md5, 32, TRUE);
                    }
                    email->firstInContent |= (1 << which);
                    email->base64Decode &= ~(1 << which);
                    email->state64[which] = 0;
                    email->save64[which] = 0;
                    g_checksum_reset(email->checksum[which]);
                    *state = EMAIL_MIME;
                } else if (*state == EMAIL_MIME_DATA_RETURN) {
                    if (email->base64Decode & (1 << which)) {
                        guchar buf[20000];
                        if (sizeof(buf) > line->len) {
                            gsize  b = g_base64_decode_step (line->str, line->len, buf,
                                                            &(email->state64[which]),
                                                            &(email->save64[which]));
                            g_checksum_update(email->checksum[which], buf, b);

                            if (email->firstInContent & (1 << which)) {
                                email->firstInContent &= ~(1 << which);
                                moloch_parsers_magic(session, magicField, (char *)buf, b);
                            }
                        }

                    }
                    *state = EMAIL_MIME_DATA;
                } else {
                    *state = EMAIL_DATA;
                }
            }

            g_string_truncate(line, 0);
            if (*data != '\n')
                continue;
            break;
        }
        case EMAIL_IGNORE: {
            return 0;
        }
        case EMAIL_TLS_OK: {
            if (*data == '\r') {
                *state = EMAIL_TLS_OK_RETURN;
                break;
            }
            g_string_append_c(line, *data);
            break;
        }
        case EMAIL_TLS_OK_RETURN: {
#ifdef EMAILDEBUG
            printf("%d %d tls => %s\n", which, *state, line->str);
#endif
            *state = EMAIL_TLS;
            if (*data != '\n')
                continue;
            break;
        }
        case EMAIL_TLS: {
            *state = EMAIL_IGNORE;
            moloch_parsers_classify_tcp(session, data, remaining, which);
            moloch_parsers_unregister(session, email);
            return 0;
        }
        case EMAIL_MIME: {

            if (*data == '\r') {
                *state = EMAIL_MIME_RETURN;
                break;
            }
            g_string_append_c(line, *data);
            break;
        }
        case EMAIL_MIME_RETURN: {
#ifdef EMAILDEBUG
            printf("%d %d mime => %s\n", which, *state, line->str);
#endif
            if (*line->str == 0) {
                *state = EMAIL_MIME_DATA;
            } else if (strcmp(line->str, ".") == 0) {
                email->needStatus[which] = 1;
                *state = EMAIL_CMD;
            } else {
                *state = EMAIL_MIME_DONE;
            }
            
            if (*data != '\n')
                continue;
            break;
        }
        case EMAIL_MIME_DONE: {
#ifdef EMAILDEBUG
            printf("%d %d mime done => %s (%c)\n", which, *state, line->str, *data);
#endif
            *state = EMAIL_MIME;

            if (*data == ' ' || *data == '\t') {
                g_string_append_c(line, *data);
                break;
            }

            if (strncasecmp(line->str, "content-type:", 13) == 0) {
                char *s = line->str + 13;
                while(isspace(*s)) s++;
                char *boundary = (char *)moloch_memcasestr(s, line->len - (s - line->str), "boundary=", 9);
                if (boundary) {
                    MolochString_t *string = MOLOCH_TYPE_ALLOC0(MolochString_t);
                    string->str = g_strdup(email_remove_matching(boundary+9, '"', '"'));
                    string->len = strlen(string->str);
                    DLL_PUSH_TAIL(s_, &email->boundaries, string);
                }
            } else if (strncasecmp(line->str, "content-disposition:", 20) == 0) {
                char *s = line->str + 13;
                while(isspace(*s)) s++;
                char *filename = (char *)moloch_memcasestr(s, line->len - (s - line->str), "filename=", 9);
                if (filename) {
                    char *matching = email_remove_matching(filename+9, '"', '"');
                    email_add_encoded(session, fnField, matching, strlen(matching));
                }
            } else if (strncasecmp(line->str, "content-transfer-encoding:", 26) == 0) {
                if(moloch_memcasestr(line->str+26, line->len - 26, "base64", 6)) {
                    email->base64Decode |= (1 << which);
                }
            }

            g_string_truncate(line, 0);
            if (*data != '\n')
                continue;
            break;
        }
        }
        data++;
        remaining--;
    }

    return 0;
}
/******************************************************************************/
void smtp_free(MolochSession_t UNUSED(*session), void *uw)
{
    SMTPInfo_t            *email          = uw;

    MolochString_t *string;

    g_string_free(email->line[0], TRUE);
    g_string_free(email->line[1], TRUE);

    g_checksum_free(email->checksum[0]);
    g_checksum_free(email->checksum[1]);

    fm_free(email->fm);
    if (email->eml_path) free(email->eml_path);

    while (DLL_POP_HEAD(s_, &email->boundaries, string)) {
        g_free(string->str);
        MOLOCH_TYPE_FREE(MolochString_t, string);
    }

    MOLOCH_TYPE_FREE(SMTPInfo_t, email);
}
/******************************************************************************/
void smtp_classify(MolochSession_t *session, const unsigned char *data, int len, int UNUSED(which), void *UNUSED(uw))
{
    if (len < 5)
        return;

    if (memcmp("HELO ", data, 5) == 0 ||
        memcmp("EHLO ", data, 5) == 0 ||
        (memcmp("220 ", data, 4) == 0 &&
         g_strstr_len((char *)data, len, "SMTP") != 0)) {

        if (moloch_session_has_protocol(session, "smtp"))
            return;

        moloch_session_add_protocol(session, "smtp");

        SMTPInfo_t *email = MOLOCH_TYPE_ALLOC0(SMTPInfo_t);

        email->line[0] = g_string_sized_new(100);
        email->line[1] = g_string_sized_new(100);

        email->checksum[0] = g_checksum_new(G_CHECKSUM_MD5);
        email->checksum[1] = g_checksum_new(G_CHECKSUM_MD5);
        email->fm = fm_init();
        email->session = session;

        DLL_INIT(s_, &(email->boundaries));

        moloch_parsers_register(session, smtp_parser, email, smtp_free);
    }
}
/******************************************************************************/
void moloch_parser_init()
{
    hostField = moloch_field_define("email", "lotermfield",
        "host.email", "Hostname", "eho",
        "Email hostnames",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "aliases", "[\"email.host\"]",
        "requiredRight", "emailSearch",
        "category", "host",
        NULL);

    uaField = moloch_field_define("email", "lotextfield",
        "email.x-mailer", "X-Mailer Header", "eua",
        "Email X-Mailer header",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "rawField", "raweua",
        "requiredRight", "emailSearch",
        NULL);

    srcField = moloch_field_define("email", "lotermfield",
        "email.src", "Sender", "esrc",
        "Email from address",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        "category", "user",
        NULL);

    dstField = moloch_field_define("email", "lotermfield",
        "email.dst", "Receiver", "edst",
        "Email to address",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        "category", "user",
        NULL);

    subField = moloch_field_define("email", "textfield",
        "email.subject", "Subject", "esub",
        "Email subject header",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT | MOLOCH_FIELD_FLAG_FORCE_UTF8,
        "rawField", "rawesub",
        "requiredRight", "emailSearch",
        NULL);

    idField = moloch_field_define("email", "termfield",
        "email.message-id", "Id", "eid",
        "Email Message-Id header",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        NULL);

    ctField = moloch_field_define("email", "termfield",
        "email.content-type", "Content-Type", "ect",
        "Email content-type header",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        NULL);

    mvField = moloch_field_define("email", "termfield",
        "email.mime-version", "Mime-Version", "emv",
        "Email Mime-Header header",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        NULL);

    fnField = moloch_field_define("email", "termfield",
        "email.fn", "Filenames", "efn",
        "Email attachment filenames",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        NULL);

    md5Field = moloch_field_define("email", "termfield",
        "email.md5", "Attach MD5s", "emd5",
        "Email attachment MD5s",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        "category", "md5",
        NULL);

    fctField = moloch_field_define("email", "termfield",
        "email.file-content-type", "Attach Content-Type", "efct",
        "Email attachment content types",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        NULL);

    ipField = moloch_field_define("email", "ip",
        "ip.email", "IP", "eip",
        "Email IP address", 
        MOLOCH_FIELD_TYPE_IP_HASH,   MOLOCH_FIELD_FLAG_CNT | MOLOCH_FIELD_FLAG_IPPRE,
        "requiredRight", "emailSearch",
        "category", "ip",
        NULL);

    hhField = moloch_field_define("email", "lotermfield",
        "email.has-header", "Header", "ehh",
        "Email has the header set",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        NULL);

    magicField = moloch_field_define("email", "termfield",
        "email.bodymagic", "Body Magic", "email.bodymagic-term",
        "The content type of body determined by libfile/magic",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_COUNT,
        NULL);
    attachIdField = moloch_field_define("smtp", "termfield",
        "smtp.attach", "Filenames", "eattach",
        "SMTP attachment id",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "attach",
        NULL);

    HASH_INIT(s_, emailHeaders, moloch_string_hash, moloch_string_cmp);
    moloch_config_add_header(&emailHeaders, "cc", dstField);
    moloch_config_add_header(&emailHeaders, "to", dstField);
    moloch_config_add_header(&emailHeaders, "from", srcField);
    moloch_config_add_header(&emailHeaders, "message-id", idField);
    moloch_config_add_header(&emailHeaders, "content-type", ctField);
    moloch_config_add_header(&emailHeaders, "subject", subField);
    moloch_config_add_header(&emailHeaders, "x-mailer", uaField);
    moloch_config_add_header(&emailHeaders, "user-agent", uaField);
    moloch_config_add_header(&emailHeaders, "mime-version", mvField);
    moloch_config_add_header(&emailHeaders, "received", receivedField);
    moloch_config_load_header("headers-email", "email", "Email header ", "email.", "hdrs.ehead-", &emailHeaders, 0);

    if (config.parseSMTP) {
        moloch_parsers_classifier_register_tcp("smtp", NULL, 0, (unsigned char*)"HELO", 4, smtp_classify);
        moloch_parsers_classifier_register_tcp("smtp", NULL, 0, (unsigned char*)"EHLO", 4, smtp_classify);
        moloch_parsers_classifier_register_tcp("smtp", NULL, 0, (unsigned char*)"220 ", 4, smtp_classify);
    }
    RIPMIME_init();
}

static void _extract_eml(void *data)
{
    SMTPInfo_t *smtp = (SMTPInfo_t *)data;
#ifdef TESTMODE
    printf("Preparing to extract file %s\n", smtp->eml_path);
#endif
    struct email_attach_file *list = NULL;
    RIPMIME_IGL_decode(smtp->eml_path, &list);
    if (!list) {
        _save_file_meta(smtp, NULL);
    }
    else {
        while (list) {
#ifdef TESTMODE
            printf("Extract file %s to %s\n", list->name, list->path);
#endif
            _save_file_meta(smtp, list);
            list = list->nxt;
        }
    }
}

static void _save_file_meta(SMTPInfo_t *smtp, struct email_attach_file *file)
{
    MolochSession_t *session = smtp->session;
    MolochExtractFile_t info;
    char buf[1000];
    sprintf(info.id, "%s-%d", moloch_session_id_string(session->sessionId, buf), smtp->filecount++);
    strcpy(info.type, "smtp");
    info.time=0;
    info.times=session->lastPacket.tv_sec;
    info.timeu=session->lastPacket.tv_usec;
    info.a1 = htonl(MOLOCH_V6_TO_V4(session->addr1));
    info.a2 = htonl(MOLOCH_V6_TO_V4(session->addr2));
    info.p1=session->port1;
    info.p2=session->port2;
    strcpy(info.eml_path, smtp->eml_path);
    info.eml_err = 0;   //TODO
    info.thread = session->thread;
    if (file) {
        strcpy(info.path, file->path);
        strcpy(info.name, file->name);
    }
    else {
        strcpy(info.path, "");
        strcpy(info.name, "");
    }
    moloch_db_save_file_extract(&info);
    char *attachid = strdup(info.id);
    moloch_field_string_add(attachIdField, session, attachid, -1, FALSE);
}
