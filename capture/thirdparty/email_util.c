#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "email_util.h"

extern MolochConfig_t   config;
extern unsigned char    moloch_hex_to_char[256][256];

/******************************************************************************/
char *
smtp_quoteable_decode_inplace(char *str, gsize *olen)
{
    char *start = str;
    int   ipos = 0;
    int   opos = 0;
    int   done = 0;

    while (str[ipos] && !done) {
        switch(str[ipos]) {
        case '=':
            if (str[ipos+1] && str[ipos+2] && str[ipos+1] != '\n') {
                str[opos] = moloch_hex_to_char[(unsigned char)str[ipos+1]][(unsigned char)str[ipos+2]];
                ipos += 2;
            } else {
                done = 1;
                continue;
            }
            break;
        case '_':
            str[opos] = ' ';
            break;
        case '?':
            if (str[ipos+1] == '=') {
                done = 1;
                continue;
            }
            str[opos] = str[ipos];
        default:
            str[opos] = str[ipos];
        }
        opos++;
        ipos++;
    }


    *olen = opos;
    str[opos] = 0;
    return start;
}


void email_add_encoded(MolochSession_t *session, int pos, char *string, int len)
{
    /* Decode this nightmare - http://www.rfc-editor.org/rfc/rfc2047.txt */
    /* =?charset?encoding?encoded-text?= */


    char  output[0xfff];
    char *str = string;
    char *end = str + len;
    GError  *error = 0;
    gsize    bread, bwritten, olen;

    BSB bsb;
    BSB_INIT(bsb, output, sizeof(output));

    while (str < end) {
        char *startquestion = strstr(str, "=?");

        /* No encoded text, or normal text in front of encoded */
        if (!startquestion || str != startquestion) {
            int extra = 0;
            if (!startquestion)
                startquestion = end;
            else if (str + 1 == startquestion && *str == ' ') {
                // If we have " =?" don't encode space, this helps with "?= =?"
                extra = 1;
            }

            char *out = g_convert((char *)str+extra, startquestion - str-extra, "utf-8", "WINDOWS-1252", &bread, &bwritten, &error);
            if (error) {
                LOG("ERROR convering %s to utf-8 %s ", "windows-1252", error->message);
                moloch_field_string_add(pos, session, string, len, TRUE);
                g_error_free(error);
                return;
            }

            BSB_EXPORT_ptr_some(bsb, out, bwritten);
            g_free(out);

            str = startquestion;
            continue;
        }

        /* Start of encoded token */
        char *question = strchr(str+2, '?');
        if (!question) {
            moloch_field_string_add(pos, session, string, len, TRUE);
            return;
        }

        char *endquestion = strstr(question+3, "?=");
        if (!endquestion) {
            moloch_field_string_add(pos, session, string, len, TRUE);
            return;
        }

        /* str+2 - question         = charset */
        /* question+1               = encoding */
        /* question+3 - endquestion = encoded-text */

        if (question+3 == endquestion) {
            // The encoded text is empty
        } else if (*(question+1) == 'B' || *(question+1) == 'b') {
            *question = 0;
            *endquestion = 0;

            g_base64_decode_inplace(question+3, &olen);

            char *out = g_convert((char *)question+3, olen, "utf-8", str+2, &bread, &bwritten, &error);
            if (error) {
                LOG("ERROR convering %s to utf-8 %s ", str+2, error->message);
                moloch_field_string_add(pos, session, string, len, TRUE);
                g_error_free(error);
                return;
            }

            BSB_EXPORT_ptr_some(bsb, out, bwritten);
            g_free(out);
        } else if (*(question+1) == 'Q' || *(question+1) == 'q') {
            *question = 0;

            smtp_quoteable_decode_inplace(question+3, &olen);

            char *out = g_convert((char *)question+3, strlen(question+3), "utf-8", str+2, &bread, &bwritten, &error);
            if (error) {
                LOG("ERROR convering %s to utf-8 %s ", str+2, error->message);
                moloch_field_string_add(pos, session, string, len, TRUE);
                g_error_free(error);
                return;
            }

            BSB_EXPORT_ptr_some(bsb, out, bwritten);
            g_free(out);
        } else {
            moloch_field_string_add(pos, session, string, len, TRUE);
            return;
        }
        str = endquestion + 2;
    }

    if (BSB_IS_ERROR(bsb)) {
        moloch_field_string_add(pos, session, output, sizeof(output), TRUE);
    }
    else {
        moloch_field_string_add(pos, session, output, BSB_LENGTH(bsb), TRUE);
    }
}

/******************************************************************************/
void email_parse_addresses(int field, MolochSession_t *session, char *data, int len)
{
    char *end = data+len;

    while (data < end) {
        while (data < end && isspace(*data)) data++;
        char *start = data;

        /* Starts with quote is easy */
        if (data < end && *data == '"') {
            data++;
            while (data < end && *data != '"') data++;
            data++;
            while (data < end && isspace(*data)) data++;
            start = data;
        }

        while (data < end && *data != '<' && *data != ',') data++;

        if (*data == '<') {
            data++;
            start = data;
            while (data < end && *data != '>') data++;
        }

        char *lower = g_ascii_strdown(start, data - start);
        if (!moloch_field_string_add(field, session, lower, data - start, FALSE)) {
            g_free(lower);
        }

        while (data < end && *data != ',') data++;
        if (data < end && *data == ',') data++;
    }
}

/******************************************************************************/
char *email_remove_matching(char *str, char start, char stop) 
{
    while (isspace(*str))
        str++;

    if (*str == start)
        str++;

    char *startstr = str;

    while (*str && *str != stop)
        str++;
    *str = 0;

    return startstr;
}
/******************************************************************************/
void email_parse_received(MolochSession_t *session, char *data, int len, int ipField, int hostField)
{
    char *start = data;
    char *end = data+len;

    while (data < end) {
        if (end - data > 10) {
            if (memcmp("from ", data, 5) == 0 && (data == start || data[-1] != '-')) {
                data += 5;
                while(data < end && isspace(*data)) data++;

                if (*data == '[') {
                    data++;
                    char *ipstart = data;
                    while (data < end && *data != ']') data++;
                    *data = 0;
                    data++;
                    in_addr_t ia = inet_addr(ipstart);
                    if (ia == 0 || ia == 0xffffffff)
                        continue;
                    moloch_field_int_add(ipField, session, ia);
                    continue;
                }

                char *fromstart = data;
                while (data < end && *data != ' ' && *data != ')') {
                    if (*data == '@')
                        fromstart = data+1;
                    data++;
                }
                char *lower = g_ascii_strdown((char*)fromstart, data - fromstart);
                if (!moloch_field_string_add(hostField, session, lower, data - fromstart, FALSE)) {
                    g_free(lower);
                }
            } else if (memcmp("by ", data, 3) == 0) {
                data += 3;
                while(data < end && isspace(*data)) data++;
                char *fromstart = data;
                while (data < end && *data != ' ' && *data != ')') {
                    if (*data == '@')
                        fromstart = data+1;
                    data++;
                }
                char *lower = g_ascii_strdown((char*)fromstart, data - fromstart);
                if (!moloch_field_string_add(hostField, session, lower, data - fromstart, FALSE)) {
                    g_free(lower);
                }
            }
        }

        if (*data == '[') {
            data++;
            char *ipstart = data;
            while (data < end && *data != ']') data++;
            *data = 0;
            in_addr_t ia = inet_addr(ipstart);
            if (ia == 0 || ia == 0xffffffff)
                continue;
            moloch_field_int_add(ipField, session, ia);
        }
        data++;
    }
}
/******************************************************************************/
void email_add_value(MolochSession_t *session, int pos, char *s, int l)
{
    while (isspace(*s)) {
        s++;
        l--;
    }

    switch (config.fields[pos]->type) {
    case MOLOCH_FIELD_TYPE_INT:
    case MOLOCH_FIELD_TYPE_INT_ARRAY:
    case MOLOCH_FIELD_TYPE_INT_HASH:
        moloch_field_int_add(pos, session, atoi(s));
        break;
    case MOLOCH_FIELD_TYPE_STR:
    case MOLOCH_FIELD_TYPE_STR_ARRAY:
    case MOLOCH_FIELD_TYPE_STR_HASH:
        moloch_field_string_add(pos, session, s, l, TRUE);
        break;
    case MOLOCH_FIELD_TYPE_IP_HASH:
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
                LOG("ERROR - Didn't understand ip: %s %s %d", s, ip, ia);
                continue;
            }

            moloch_field_int_add(pos, session, ia);
        }

        g_strfreev(parts);
        break;
    }
    } /* SWITCH */
}
