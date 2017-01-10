#ifndef __FILE_MANAGER__
#define __FILE_MANAGER__

#define HTTP_URI 1
#define HTTP_HOST 2
#define HTTP_RANGE 3
#define HTTP_CONTENT_TYPE 4
#define HTTP_CONTENT_LEN 5
#define HTTP_STATUS_CODE 6
#define HTTP_SAVEFILE 7

#define STR_LEN 1024
#define URL_LEN 2048

typedef struct _fm_t fm_t;

fm_t *fm_init(void);
void fm_free(fm_t *fm);
int fm_open(fm_t *fm, const char *filename, size_t fsize);
int fm_write(fm_t *fm, const char *buf, size_t buflen);
int fm_add_cb(fm_t *fm, void (*complete_cb)(void *data), void *data);
int fm_set_data(fm_t *fm, void *data);
void fm_close(fm_t *fm);
int fm_set_filetype(fm_t *fm, const char *type);

#endif
