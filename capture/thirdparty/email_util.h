#ifndef __EMAIL_UTIL_H__
#define __EMAIL_UTIL_H__

#include "moloch.h"

void email_add_encoded(MolochSession_t *session, int pos, char *string, int len);
void email_parse_addresses(int field, MolochSession_t *session, char *data, int len);
char *email_remove_matching(char *str, char start, char stop);
void email_parse_received(MolochSession_t *session, char *data, int len, int ipField, int hostField);
void email_add_value(MolochSession_t *session, int pos, char *s, int l);
#endif
