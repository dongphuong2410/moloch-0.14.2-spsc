#include <string.h>
#include <ctype.h>
#include <ripmime-api.h>
#include <mime.h>
#include "moloch.h"
#include "file_manager.h"
#include "common.h"
#include "email_util.h"

typedef struct {
    MolochStringHead_t boundaries;
    char        state[2];
    char               needStatus[2];
    GString     *line[2];
    fm_t        *fm;
    gint               state64[2];
    guint              save64[2];
    GChecksum         *checksum[2];
    uint16_t           base64Decode:2;
    uint16_t           firstInContent:2;
    char               *eml_path;
    MolochSession_t    *session;
    uint32_t           filecount;
} POPInfo_t;

enum {
    EMAIL_CMD,
    EMAIL_CMD_RETURN,

    EMAIL_HEADER,
    EMAIL_HEADER_RETURN,
    EMAIL_HEADER_DONE,
    EMAIL_HEADER_RESPONSE_CHECK,
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
static void _save_file_meta(POPInfo_t *pop, struct email_attach_file *file);

extern MolochConfig_t   config;
static MolochStringHashStd_t emailHeaders;
static int receivedField;
static int idField;
static int ipField;
static int hostField;
static int srcField;
static int dstField;
static int md5Field;
static int fnField;
static int userField;
static int subField;
static int ctField;
static int mvField;
static int magicField;
static int attachIdField;

/******************************************************************************/
void pop_parser(MolochSession_t *session, void *uw, const unsigned char *data, int remaining, int which)
{
    POPInfo_t *pop = uw;
    char *state = &pop->state[which];
    GString *line = pop->line[which];
    MolochString_t *emailHeader = 0;
    char filepath[1024];

    if (*state == EMAIL_HEADER_RESPONSE_CHECK) {
        if (strncmp((const char *)data, "+OK", 3) == 0) {
            char *endline = strstr((const char *)data, "\r\n");
            if (endline != 0) {
                int skip = (endline - (char *)data) + 2;//Jump to the start of next line
                data += skip;
                remaining -= skip;
            }
            *state = EMAIL_HEADER;
            pop->eml_path = (char *)malloc(sizeof(char) * 1024);
            sprintf(filepath, "%s/pop_eml_%ld", config.fileExtractDir, time(NULL));
            cm_get_uniq_name(filepath, pop->eml_path);
            fm_open(pop->fm, pop->eml_path, 1000000);
            if (config.emlExtract) {
                fm_add_cb(pop->fm, _extract_eml, pop);
            }
        }
        else {
            *state = EMAIL_CMD;
        }
    }
    if (*state == EMAIL_HEADER || *state == EMAIL_DATA || *state == EMAIL_MIME_DATA) {
        fm_write(pop->fm, (const char *)data, remaining);
    }
    while (remaining > 0) {
        switch (*state) {
        case EMAIL_CMD:
            if (*data == '\r') {
                (*state)++;
                break;
            }
            g_string_append_c(line, *data);
            break;
        case EMAIL_CMD_RETURN:
#ifdef TESTMODE
                    printf("CMD => %s\n", line->str);
#endif
            if (strncasecmp(line->str, "RETR", 4) == 0) {
                pop->state[(which + 1) % 2] = EMAIL_HEADER_RESPONSE_CHECK;
            }
            else if (strncasecmp(line->str, "STLS", 4) == 0) {
                moloch_session_add_tag(session, "pop:starttls");
                *state = EMAIL_IGNORE;
                pop->state[(which + 1) % 2] = EMAIL_TLS_OK;
                return;
            }
            else {
                *state = EMAIL_CMD;
            }
            g_string_truncate(line, 0);
            if (*data != '\n')
                continue;
            break;
        case EMAIL_HEADER:
            if (*data == '\r') {
                *state = EMAIL_HEADER_RETURN;
                break;
            }
            g_string_append_c(line, *data);
            break;
        case EMAIL_HEADER_RETURN:
            if (strcmp(line->str, ".") == 0) {
                g_string_truncate(line, 0);
                *state = EMAIL_CMD;
            }
            else if (*line->str == 0) {
                *state = EMAIL_DATA;
            }
            else {
                *state = EMAIL_HEADER_DONE;
            }
            if (*data != '\n')
                continue;
            break;
        case EMAIL_HEADER_DONE:
            *state = EMAIL_HEADER;

            if (*data == ' ' || *data == '\t') {
                g_string_append_c(line, ' ');
                break;
            }
            char *colon = strchr(line->str, ':');
            if (!colon) {
                g_string_truncate(line, 0);
                if (*data != '\n')
                    continue;
                break;
            }
            char *lower = g_ascii_strdown(line->str, colon - line->str);
            HASH_FIND(s_, emailHeaders, lower, emailHeader);
            if (emailHeader) {
                int cpos = colon - line->str + 1;
                if ((long)emailHeader->uw == subField) {
                    if (line->str[8] != ' ') {
                        moloch_session_add_tag(session, "pop:missing-subject-space");
                        email_add_encoded(session, subField, line->str+8, line->len-8);
                    }
                    else {
                        email_add_encoded(session, subField, line->str+8, line->len-8);
                    }
                } else if ((long)emailHeader->uw == dstField) {
                    email_parse_addresses(dstField, session, line->str+cpos, line->len-cpos);
                } else if ((long)emailHeader->uw == srcField) {
                    email_parse_addresses(srcField, session, line->str+cpos, line->len-cpos);
                } else if ((long)emailHeader->uw == idField) {
                    moloch_field_string_add(idField, session, email_remove_matching(line->str+cpos, '<', '>'), -1, TRUE);
                } else if ((long)emailHeader->uw == receivedField) {
                    email_parse_received(session, line->str + cpos, line->len-cpos, ipField, hostField);
                } else if ((long)emailHeader->uw == ctField) {
                    char *s = line->str + 13;
                    while(isspace(*s)) s++;

                    moloch_field_string_add(ctField, session, s, -1, TRUE);
                    char *boundary = (char *)moloch_memcasestr(s, line->len - (s - line->str), "boundary=", 9);
                    if (boundary) {
                        MolochString_t *string = MOLOCH_TYPE_ALLOC0(MolochString_t);
                        string->str = g_strdup(email_remove_matching(boundary+9, '"', '"'));
                        string->len = strlen(string->str);
                        DLL_PUSH_TAIL(s_, &pop->boundaries, string);
                    }
                } else {
                    email_add_value(session, (long)emailHeader->uw, line->str + cpos, line->len -cpos);
                }
            }
            g_free(lower);
            g_string_truncate(line, 0);
            if (*data != '\n')
                continue;
            break;
        case EMAIL_MIME_DATA:
        case EMAIL_DATA:
            if (*data == '\r') {
                (*state)++;
                break;
            }
            g_string_append_c(line, *data);
            break;
        case EMAIL_MIME_DATA_RETURN:
        case EMAIL_DATA_RETURN:
            if (strcmp(line->str, ".") == 0) {
                *state = EMAIL_CMD;
                fm_close(pop->fm);
            }
            else {
                MolochString_t *string;
                gboolean found = FALSE;
                if (line->str[0] == '-') {
                    DLL_FOREACH(s_, &pop->boundaries, string) {
                        if ((int)line->len >= (int)(string->len + 2) && memcmp(line->str+2, string->str, string->len) == 0) {
                            found = TRUE;
                            break;
                        }
                    }
                }
                if (found) {
                    if (pop->base64Decode & (1 << which)) {
                        const char *md5 = g_checksum_get_string(pop->checksum[which]);
                        moloch_field_string_add(md5Field, session, (char *)md5, 32, TRUE);
                    }
                    pop->firstInContent |= (1 << which);
                    pop->base64Decode &= ~(1 << which);
                    pop->state64[which] = 0;
                    pop->save64[which] = 0;
                    g_checksum_reset(pop->checksum[which]);
                    *state = EMAIL_MIME;
                } else if (*state == EMAIL_MIME_DATA_RETURN) {
                    if (pop->base64Decode & (1 << which)) {
                        guchar buf[20000];
                        if (sizeof(buf) > line->len) {
                            gsize b = g_base64_decode_step(line->str, line->len, buf, &(pop->state64[which]), &(pop->save64[which]));
                            g_checksum_update(pop->checksum[which], buf, b);
                            if (pop->firstInContent & (1 << which)) {
                                pop->firstInContent &= ~(1 << which);
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
        case EMAIL_MIME:
            if (*data == '\r') {
                *state = EMAIL_MIME_RETURN;
                break;
            }
            g_string_append_c(line, *data);
            break;
        case EMAIL_MIME_RETURN:
#ifdef EMAILDEBUG
            printf("%d %d mime => %s\n", which, *state, line->str);
#endif
            if (*line->str == 0) {
                *state = EMAIL_MIME_DATA;
            } else if (strcmp(line->str, ".") == 0) {
                pop->needStatus[which] = 1;
                *state = EMAIL_CMD;
            } else {
                *state = EMAIL_MIME_DONE;
            }
            if (*data != '\n')
                continue;
            break;
        case EMAIL_MIME_DONE:
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
                    DLL_PUSH_TAIL(s_, &pop->boundaries, string);
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
                    pop->base64Decode |= (1 << which);
                }
            }

            g_string_truncate(line, 0);
            if (*data != '\n')
                continue;
            break;
        case EMAIL_IGNORE:
            return;
        case EMAIL_TLS_OK:
            if (*data == '\r') {
                *state = EMAIL_TLS_OK_RETURN;
                break;
            }
            g_string_append_c(line, *data);
            break;
        case EMAIL_TLS_OK_RETURN:
            *state = EMAIL_TLS;
            if (*data != '\n')
                continue;
            break;
        case EMAIL_TLS:
            *state = EMAIL_IGNORE;
            moloch_parsers_classify_tcp(session, data, remaining, which);
            moloch_parsers_unregister(session, pop);
            break;
        }
        remaining--;
        data++;
    }
}
/******************************************************************************/
void pop_free(MolochSession_t UNUSED(*session), void *uw)
{
    POPInfo_t            *pop          = uw;
    g_string_free(pop->line[0], TRUE);
    g_string_free(pop->line[1], TRUE);

    g_checksum_free(pop->checksum[0]);
    g_checksum_free(pop->checksum[1]);

    fm_free(pop->fm);
    if (pop->eml_path) free(pop->eml_path);
    MolochString_t *string;
    while (DLL_POP_HEAD(s_, &pop->boundaries, string)) {
        g_free(string->str);
        MOLOCH_TYPE_FREE(MolochString_t, string);
    }
    MOLOCH_TYPE_FREE(POPInfo_t, pop);
}
/******************************************************************************/
void pop_classify(MolochSession_t *session, const unsigned char *data, int len)
{
    if (len < 4)
        return;
    if (memcmp(data, "+OK", 3) == 0 && session->port2 == 110 ) {
        if (moloch_session_has_protocol(session, "pop"))
            return;
        moloch_session_add_protocol(session, "pop");
        POPInfo_t *pop = MOLOCH_TYPE_ALLOC0(POPInfo_t);
        pop->line[0] = g_string_sized_new(100);
        pop->line[1] = g_string_sized_new(100);
        pop->checksum[0] = g_checksum_new(G_CHECKSUM_MD5);
        pop->checksum[1] = g_checksum_new(G_CHECKSUM_MD5);
        pop->fm = fm_init();
        pop->session = session;
        DLL_INIT(s_, &(pop->boundaries));

        moloch_parsers_register(session, pop_parser, pop, pop_free);
    }
}
/******************************************************************************/
void moloch_parser_init()
{
    idField = moloch_field_define("pop", "termfield",
        "pop.message-id", "Id", "eid",
        "Email Message-Id header",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        NULL);
    ipField = moloch_field_define("pop", "ip",
        "pop.ip", "IP", "eip",
        "Email IP address",
        MOLOCH_FIELD_TYPE_IP_HASH,   MOLOCH_FIELD_FLAG_CNT | MOLOCH_FIELD_FLAG_IPPRE,
        "requiredRight", "emailSearch",
        "category", "ip",
        NULL);
    hostField = moloch_field_define("pop", "lotermfield",
        "pop.host", "Hostname", "eho",
        "Email hostnames",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "aliases", "[\"email.host\"]",
        "requiredRight", "emailSearch",
        "category", "host",
        NULL);
    srcField = moloch_field_define("pop", "lotermfield",
        "pop.src", "Sender", "esrc",
        "Email from address",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        "category", "user",
        NULL);

    dstField = moloch_field_define("pop", "lotermfield",
        "pop.dst", "Receiver", "edst",
        "Email to address",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        "category", "user",
        NULL);
    userField = moloch_field_define("pop", "lotermfield",
        "pop.user", "User", "edst",
        "Username",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        "category", "user",
        NULL);
    md5Field = moloch_field_define("pop", "termfield",
        "pop.md5", "Attach MD5s", "emd5",
        "Email attachment MD5s",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        "category", "md5",
        NULL);
    fnField = moloch_field_define("pop", "termfield",
        "pop.fn", "Filenames", "efn",
        "Email attachment filenames",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        NULL);


    subField = moloch_field_define("pop", "textfield",
        "pop.subject", "Subject", "esub",
        "Email subject header",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT | MOLOCH_FIELD_FLAG_FORCE_UTF8,
        "rawField", "rawesub",
        "requiredRight", "emailSearch",
        NULL);
    ctField = moloch_field_define("pop", "termfield",
        "pop.content-type", "Content-Type", "ect",
        "Email content-type header",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        NULL);

    mvField = moloch_field_define("pop", "termfield",
        "pop.mime-version", "Mime-Version", "emv",
        "Email Mime-Header header",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "emailSearch",
        NULL);
    magicField = moloch_field_define("email", "termfield",
        "email.bodymagic", "Body Magic", "email.bodymagic-term",
        "The content type of body determined by libfile/magic",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_COUNT,
        NULL);
    attachIdField = moloch_field_define("pop", "termfield",
        "pop.attach", "Filenames", "eattach",
        "POP attachment id",
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
    moloch_config_add_header(&emailHeaders, "mime-version", mvField);
    moloch_parsers_classifier_register_tcp("pop", NULL, 0, "+OK", 3, pop_classify);
}

static void _extract_eml(void *data)
{
    POPInfo_t *pop = (POPInfo_t *)data; 
#ifdef TESTMODE
    printf("Preparing to extract file %s\n", pop->eml_path);
#endif
    struct email_attach_file *list = NULL;
    RIPMIME_IGL_decode(pop->eml_path, &list);
    if (!list) {
        _save_file_meta(pop, NULL);
    }
    else {
        while (list) {
#ifdef TESTMODE
            printf("Extract file %s to %s\n", list->name, list->path);
#endif
            _save_file_meta(pop, list);
            list = list->nxt;
        }
    }
}

static void _save_file_meta(POPInfo_t *pop, struct email_attach_file *file)
{
    MolochSession_t *session = pop->session;
    MolochExtractFile_t info;
    char buf[1000];
    sprintf(info.id, "%s-%d", moloch_session_id_string(session->sessionId, buf), pop->filecount++);
    strcpy(info.type, "pop");
    info.time=0;
    info.times=session->lastPacket.tv_sec;
    info.timeu=session->lastPacket.tv_usec;
    info.a1 = htonl(MOLOCH_V6_TO_V4(session->addr1));
    info.a2 = htonl(MOLOCH_V6_TO_V4(session->addr2));
    info.p1=session->port1;
    info.p2=session->port2;
    strcpy(info.eml_path, pop->eml_path);
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
