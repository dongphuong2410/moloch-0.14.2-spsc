#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "moloch.h"

#define STR_DIM 1024

typedef struct {
    char                state[2];
    char                *line[2];
    int                 ip_specified;
    struct in6_addr     dataIp;
    uint16_t            dataPort;
    char                filename[STR_DIM];
    long long unsigned int fpd;
    long long unsigned int lpd;
    uint8_t             ipver;
    int                 listcnt;
    int                 filecount;
    MolochSession_t     *session;
} FTPInfo_t;

enum {
    FTP_CMD,
    FTP_CMD_RETURN
};

typedef enum _ftp_cmd ftp_cmd;
enum _ftp_cmd {
    FTP_CMD_NONE,
    FTP_CMD_USER,
    FTP_CMD_LIST,
    FTP_CMD_STOR,
    FTP_CMD_RETR,
    FTP_CMD_PORT
};

typedef enum _ftp_rep ftp_rep;
enum _ftp_rep {
    FTP_REP_NONE,
    FTP_REP_227,
    FTP_REP_228,
    FTP_REP_229
};

extern MolochConfig_t   config;
extern int userField;
static int listField;
static int fnField;
static int dataPortField;
static int dataIpField;
static int ipVerField;
static int attachIdField;

/******************************************************************************/

/**
  * Get FTP command
  */
static ftp_cmd _get_cmd(const char *line, char *param);
/**
  * Get FTP Reply
  */
static ftp_rep _get_reply(const char *line, char *param);
/**
  * Parse filename on RETR or STOR command
  */
static int _parse_filename(FTPInfo_t *ftp, const char *line);
/**
  * Parse FTP Passive mode (h1, h2, h3, h4, p1, p2)
  */
static int _parse_passive(FTPInfo_t *ftp, const char *line);
/**
  * Parse FTP Long Passive mode (long address, port)
  */
static int _parse_lpassive(FTPInfo_t *ftp, const char *line);
/**
  * Parse FTP Extended Passive mode (|||port|)
  */
static int _parse_epassive(FTPInfo_t *ftp, const char *line, int req);
/**
  * Save attach file info to elastic search database
  */
static void _save_file_meta(FTPInfo_t *ftp);

int _is_rtf2428_delimiter(char c);

void ftp_parser(MolochSession_t *session, void *uw, const unsigned char *data, int remaining, int which)
{
    FTPInfo_t            *ftp          = uw;
    char *state = &ftp->state[which];
    GString *line = ftp->line[which];
    ftp_cmd cmd;
    ftp_rep rep;
    char param[STR_DIM];

    while (remaining > 0) {
        switch (*state) {
            case FTP_CMD:
                if (*data == '\r') {
                    (*state)++;
                    break;
                }
                g_string_append_c(line, *data);
                break;
            case FTP_CMD_RETURN:
                if (!which) {
                    cmd = _get_cmd(line->str, param);
                    switch (cmd) {
                        case FTP_CMD_USER:
                            moloch_field_string_add(userField, session, param, -1, FALSE);
                            break;
                        case FTP_CMD_LIST:
                            break;
                        case FTP_CMD_PORT:
                            _parse_passive(ftp, param);
                            break;
                        case FTP_CMD_STOR:
                        case FTP_CMD_RETR:
                            if (ftp->ip_specified)
                                moloch_field_int_add(dataIpField, session, htonl(MOLOCH_V6_TO_V4(ftp->dataIp)));
                            moloch_field_int_add(dataPortField, session, ftp->dataPort);
                            _parse_filename(ftp, param);
                            _save_file_meta(ftp);
                            break;
                    }
                }
                else {
                    rep = _get_reply(line->str, param);
                    switch (rep) {
                        case FTP_REP_227:
                            _parse_passive(ftp, param);
                            break;
                        case FTP_REP_228:
                            _parse_lpassive(ftp, param);
                            break;
                        case FTP_REP_229:
                            _parse_epassive(ftp, param, which ? 0 : 1);
                            break;
                    }
                }

                *state = FTP_CMD;
                g_string_truncate(line, 0);
                if (*data != '\n')
                    continue;
                break;
        }
        remaining--;
        data++;
    }
}
/******************************************************************************/
void ftp_free(MolochSession_t UNUSED(*session), void *uw)
{
    FTPInfo_t            *ftp          = uw;

    MOLOCH_TYPE_FREE(FTPInfo_t, ftp);
}

/******************************************************************************/
void ftp_classify(MolochSession_t *session, const unsigned char *data, int UNUSED(len))
{
    if (len < 4) return;
    if (session->port2 == 21) {
        if (moloch_session_has_tag(session, "protocol:ftp"))
            return;

        moloch_session_add_tag(session, "protocol:ftp");
        FTPInfo_t            *ftp          = MOLOCH_TYPE_ALLOC0(FTPInfo_t);
        ftp->line[0] = g_string_sized_new(100);
        ftp->line[1] = g_string_sized_new(100);
        ftp->session = session;

        moloch_parsers_register(session, ftp_parser, ftp, ftp_free);
    }
}

/******************************************************************************/
void moloch_parser_init()
{
    listField = moloch_field_define("ftp", "termfield",
        "ftp.list-count", "List Count", "flist",
        "File List Count",
        MOLOCH_FIELD_TYPE_INT_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "ftpSearch",
        NULL);
    fnField = moloch_field_define("ftp", "termfield",
        "ftp.fn", "Filenames", "efn",
        "FTP attachment filenames",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "filename",
        NULL);
    attachIdField = moloch_field_define("ftp", "termfield",
        "ftp.attach", "Filenames", "eattach",
        "FTP attachment id",
        MOLOCH_FIELD_TYPE_STR_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "attach",
        NULL);
    dataPortField = moloch_field_define("ftp", "termfield",
        "ftp.data-port", "Data Port", "edataport",
        "FTP Data Port",
        MOLOCH_FIELD_TYPE_INT_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "dataPort",
        NULL);
    dataIpField = moloch_field_define("ftp", "termfield",
        "ftp.data-ip", "Data Ip Address", "edataip",
        "FTP Ip Address",
        MOLOCH_FIELD_TYPE_INT_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "dataIp",
        NULL);
    ipVerField = moloch_field_define("ftp", "termfield",
        "ftp.ip-ver", "Ip Version", "eipver",
        "FTP Ip Version",
        MOLOCH_FIELD_TYPE_INT_HASH,  MOLOCH_FIELD_FLAG_CNT,
        "requiredRight", "ipVer",
        NULL);

    moloch_parsers_classifier_register_tcp("ftp", NULL, 0, "220", 3, ftp_classify);
    moloch_parsers_classifier_register_tcp("ftp", NULL, 0, "200", 3, ftp_classify);
}

static ftp_cmd _get_cmd(const char *line, char *param)
{
    if (strncasecmp(line, "USER", 4) == 0) {
        strncpy(param, line + 5, STR_DIM);
        return FTP_CMD_USER;
    }
    else if (strncasecmp(line, "LIST", 4) == 0) {
        return FTP_CMD_LIST;
    }
    else if (strncasecmp(line, "STOR", 4) == 0) {
        strncpy(param, line + 5, STR_DIM);
        return FTP_CMD_STOR;
    }
    else if (strncasecmp(line, "RETR", 4) == 0) {
        strncpy(param, line + 5, STR_DIM);
        return FTP_CMD_RETR;
    }
    else if (strncasecmp(line, "PORT", 4) == 0) {
        strncpy(param, line + 5, STR_DIM);
        return FTP_CMD_PORT;
    }
    return FTP_CMD_NONE;
}

static ftp_rep _get_reply(const char *line, char *param)
{
    if (strncasecmp(line, "227", 3) == 0) {
        strncpy(param, line + 4, STR_DIM);
        return FTP_REP_227;
    }
    else if (strncasecmp(line, "228", 3) == 0) {
        strncpy(param, line + 3, STR_DIM);
        return FTP_CMD_LIST;
    }
    else if (strncasecmp(line, "229", 3) == 0) {
        strncpy(param, line + 3, STR_DIM);
        return FTP_CMD_STOR;
    }
    return FTP_REP_NONE;
}

static int _parse_filename(FTPInfo_t *ftp, const char *line)
{
    char *filename;
    char *slash = strrchr(line, '/');
    if (slash)
        filename = strndup(slash + 1, STR_DIM);
    else
        filename = strndup(line, STR_DIM);
    strcpy(ftp->filename, filename);
    moloch_field_string_add(fnField, ftp->session, filename, -1, FALSE);

    return 0;
}

static int _parse_passive(FTPInfo_t *ftp, const char *line)
{
    char *p;
    unsigned char c;
    int address[4], port[2];
    int ret = 0;
    int i;

    ftp->ip_specified = 0;
    p = line;
    for (;;) {
        while ((c = *p) != '\0' && !isdigit(c))
            p++;
        if (*p == '\0') {
            /*
             * We run out of text without finding anything
             */
            break;
        }
        /*
         * See if we have six numbers
         */
        i = sscanf(p, "%d,%d,%d,%d,%d,%d", &address[0], &address[1], &address[2], &address[3],
                            &port[0], &port[1]);
        if (i == 6) {
            /*
             * We have a winner
             */
            struct in_addr in;
            in.s_addr = htonl((address[0] << 24) | (address[1] << 16) | (address[2] << 8) | address[3]);
            ftp->ip_specified = 1;
            ((uint32_t *)ftp->dataIp.s6_addr)[0] = 0;
            ((uint32_t *)ftp->dataIp.s6_addr)[1] = 0;
            ((uint32_t *)ftp->dataIp.s6_addr)[2] = htonl(0xffff);
            ((uint32_t *)ftp->dataIp.s6_addr)[3] = in.s_addr;
            ftp->dataPort = ((port[0] & 0xFF) << 8) | (port[1] & 0xFF);
            ret = 1;
            break;
        }
        /*
         * Well, that didn't work. Skip the first number we found and keep trying
         */
        while ((c = *p) != '\0' && isdigit(c))
            p++;
    }
    return ret;
}

static int _parse_lpassive(FTPInfo_t *ftp, const char *line)
{
    ftp->ip_specified = 0;
    return 0;
}

static int _parse_epassive(FTPInfo_t *ftp, const char *line, int req)
{
    char *args, *p, *field;
    char delimiter;
    int n, delimiters_seen, fieldlen, lastn;
    int linelen = strlen(line);
    char buff[linelen];
    int ipver;
    struct in_addr ip4;
    struct in6_addr ip6;

    ftp->ip_specified = 0;
    if (line == NULL || linelen < 4)
        return -1;
    if (req) {
        args = strchr(line, ' ');
    }
    else {
        args = strchr(line, '(');
    }
    if (args == NULL) {
        return -1;
    }
    args++;
    p = args;
    linelen -= (p - line);

    /*
     * RFC2428 sect. 2 states ...
     *
     *     The EPRT command keyword MUST be followed by a single space (ASCII
     *     32). Following the space, a delimiter character (<d>) MUST be
     *     specified.
     *
     * ... the preceding <space> is already stripped so we know that the first
     * character must be the delimiter and has just to be checked to be valid.
     */
    if (!_is_rtf2428_delimiter(*p)) {
        return -1;
    }
    delimiter = *p;
    delimiters_seen = 0;
    /* Validate that the deliiter occurs 4 times in the string */
    for (n = 0; n < linelen; n++) {
        if (*(p + n)== delimiter)
            delimiters_seen++;
    }
    if (delimiters_seen != 4)
        return -1;

    /* the first character is a delimiter */
    delimiters_seen = 1;
    lastn = 0;
    for (n = 1; n < linelen; n++) {
        if (*(p + n) != delimiter)
            continue;

        delimiters_seen++;
        fieldlen = n - lastn - 1;
        if (fieldlen <= 0 && req)
            return -1;   /* all fields must have data in them */
        field = p + lastn + 1;
        if (delimiters_seen == 2) { /* end of address family field */
            strncpy(buff, field, fieldlen);
            buff[fieldlen] = '\0';
            switch (atoi(buff)) {
                case 1:
                    ipver = 4;
                    break;
                case 2:
                    ipver = 6;
                    break;
            }
            ftp->ipver = ipver;
        }
        else if (delimiters_seen == 3 && req) {/* end of IP address field */
            strncpy(buff, field, fieldlen);
            buff[fieldlen] = '\0';
            if (ipver == 4) {
                if (inet_pton(AF_INET, buff, &(ip4.s_addr)) <= 0)
                    return -1;
                ((uint32_t *)ftp->dataIp.s6_addr)[0] = 0;
                ((uint32_t *)ftp->dataIp.s6_addr)[1] = 0;
                ((uint32_t *)ftp->dataIp.s6_addr)[2] = htonl(0xffff);
                ((uint32_t *)ftp->dataIp.s6_addr)[3] = ip4.s_addr;
            }
            else if (ipver == 6) {
                if (inet_pton(AF_INET6, buff, &(ip6.s6_addr)) <= 0)
                   return -1;
                ftp->dataIp = ip6;
            }
            else {
                return -1;
            }
            ftp->ip_specified = 1;
        }
        else if (delimiters_seen == 4) {
            strncpy(buff, field, fieldlen);
            buff[fieldlen] = '\0';
            ftp->dataPort = atoi(buff);
        }
        lastn = n;
    }
    return 0;
}

int _is_rtf2428_delimiter(char c)
{
    static const char forbidden[] = {"0123456789abcdef.:"};
    if (c < 33 || c > 126)
        return 0;
    else if (strchr(forbidden, tolower(c)))
        return 0;
    else
        return 1;
}

static void _save_file_meta(FTPInfo_t *ftp)
{
    MolochExtractFile_t info;
    MolochSession_t *session = ftp->session;
    char buf[1000];
    sprintf(info.id, "%s-%d", moloch_session_id_string(session->sessionId, buf), ftp->filecount++);
    strcpy(info.type, "ftp");
    info.time=0;
    info.times=session->lastPacket.tv_sec;
    info.timeu=session->lastPacket.tv_usec;
    info.a1 = htonl(MOLOCH_V6_TO_V4(session->addr1));
    info.a2 = htonl(MOLOCH_V6_TO_V4(session->addr2));
    info.p1=session->port1;
    info.p2=session->port2;
    strcpy(info.filename, ftp->filename);
    info.dataIp = htonl(MOLOCH_V6_TO_V4(ftp->dataIp));
    info.dataPort = ftp->dataPort;
    info.fpd = ((uint64_t)session->firstPacket.tv_sec)*1000 + ((uint64_t)session->firstPacket.tv_usec)/1000;
    info.thread = ftp->session->thread;
    info.lpd = ((uint64_t)session->lastPacket.tv_sec)*1000 + ((uint64_t)session->lastPacket.tv_usec)/1000;
    moloch_db_save_file_extract(&info);
    char *attachid = strdup(info.id);
    moloch_field_string_add(attachIdField, session, attachid, -1, FALSE);
}
