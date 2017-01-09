#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "common.h"

static pthread_mutex_t lock;

void cm_get_uniq_name(const char *inname, char *outname)
{
    static unsigned int idx = 0;
    pthread_mutex_lock(&lock);
    strcpy(outname, inname);
    while (!access(outname, F_OK)) {
        idx++;
        sprintf(outname, "%s_%lu", inname, idx);
    }
    pthread_mutex_unlock(&lock);
}

const char * cm_extract_filename(const char *path)
{
    if (path) {
        char *lastSlash = strrchr(path, '/');
        if (lastSlash)
            return (const char *)(lastSlash + 1);
        else
            return path;
    }
    return "";
}
