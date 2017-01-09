#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "file_manager.h"
#include "common.h"

#define MAX_CB 5

typedef void (*on_complete_t)(void *data);

struct _fm_t {
    FILE            *fp;
    size_t          filesize;
    size_t          bytes_read;
    int             is_multipart;
    on_complete_t   on_complete[MAX_CB];
    void            *data[MAX_CB]; //Share data between fm_t object and caller
    int             cb_no;
};

/*
 * Create new fm object
 */
fm_t *fm_init(void)
{
    fm_t *fm = (fm_t *)calloc(1, sizeof(fm_t ));
}

void fm_close(fm_t *fm)
{
    if (fm->fp) {
        fclose(fm->fp);
        fm->fp = NULL;
    }
    int i;
    for (i = 0; i < fm->cb_no; i++) {
        fm->on_complete[i](fm->data[i]);
    }
    fm->is_multipart = 0;
    fm->cb_no = 0;
}
void fm_free(fm_t *fm)
{
    fm_close(fm);
    free(fm);
}

int fm_open(fm_t *fm, const char *filename, size_t fsize)
{
#ifdef TESTMODE
    printf("INFO Extracting file %s : %lu bytes \n", filename, fsize);
#endif
    fm->filesize = fsize;
    fm->bytes_read = 0;
    if (!(fm->fp = fopen(filename, "w")))
        return -1;
    return 0;
}

/**
 * Write data to file, return 0 if file is not completed yet
 * Return 1 if file is completed
 */
int fm_write(fm_t *fm, const char *buf, size_t buflen)
{
    if (!fm->fp) return 0;
    fwrite(buf, 1, buflen, fm->fp);
    fm->bytes_read += buflen;
    if (fm->filesize > 0 && fm->filesize <= fm->bytes_read) {
        fm_close(fm);
        return 1;
    }
    return 0;
}

int fm_add_cb(fm_t *fm, on_complete_t complete_cb, void *data)
{
    if (fm->cb_no >= MAX_CB) {
        printf("ERROR max callbacks exceeded\n");
        return -1;
    }
    fm->on_complete[fm->cb_no] = complete_cb;
    fm->data[fm->cb_no] = data;
    fm->cb_no++;
    return 0;
}

