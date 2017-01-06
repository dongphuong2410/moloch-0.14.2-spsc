#ifndef __CURL_WRAPPER_H__
#define __CURL_WRAPPER_H__

#include <curl/curl.h>

typedef void (*recv_cb)(char *ptr, void* user_data);

enum
{
	CURL_WRAPPER_GET,
	CURL_WRAPPER_POST,
	CURL_WRAPPER_DELETE
};

typedef struct
{
	char *ptr;
	size_t len;
}string;

typedef struct
{
	CURL* curl;
	int method;
	string str;
	char* host;
	int host_len;

	char* url;
	int url_len;
	char* uri;
	char* data;
	recv_cb cb;
}CurlWrapper_t;

CurlWrapper_t* http_init(char* hostname);
void http_param_set(CurlWrapper_t* wrapper, int method, char* url, char* data, recv_cb cb);
int http_send(CurlWrapper_t* wrapper, void* user_data);
void http_reuse(CurlWrapper_t* wrapper);
void http_destroy(CurlWrapper_t* wrapper);

#endif
