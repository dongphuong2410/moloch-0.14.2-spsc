#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "curl_wrapper.h"

int init_string(string *s) {
	s->len = 0;
	s->ptr = malloc(s->len + 1);
	if (s->ptr == NULL) {
		printf("init_string failed\n");
		return 0;
	}
	s->ptr[0] = '\0';
	return 1;
}

void free_string(string *s)
{
	if(s->ptr) free(s->ptr);
}

CurlWrapper_t* http_init(char* hostname)
{
	CurlWrapper_t* wrapper = malloc(sizeof(CurlWrapper_t));
	wrapper->curl = curl_easy_init();
	wrapper->method = CURL_WRAPPER_GET;

	int host_len = strlen(hostname);
	wrapper->host = malloc(host_len + 1);
	memcpy(wrapper->host, hostname, host_len);
	wrapper->host[host_len] = '\0';
	wrapper->host_len = strlen(hostname);
	wrapper->url = 0;
	wrapper->url_len = 0;
	wrapper->uri = 0;
	wrapper->data = 0;

	return wrapper;
}

void http_reuse(CurlWrapper_t* wrapper)
{
	if(wrapper->uri) {
		free(wrapper->uri);
		wrapper->uri = NULL;
	}
	char* tmp = wrapper->host;
	free_string(&(wrapper->str));
	wrapper->str.ptr = NULL;
	curl_easy_reset(wrapper->curl);
	wrapper->host = tmp;
}

void http_param_set(CurlWrapper_t* wrapper, int method, char* url, char* data, recv_cb cb)
{
	wrapper->url = url;
	wrapper->url_len = strlen(url);
	wrapper->data = data;
	wrapper->cb = cb;
	wrapper->method = method;
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, void *user_data)
{
	string *s = (string *)user_data;
	size_t new_len = s->len + size*nmemb;
	s->ptr = realloc(s->ptr, new_len+1);
	if (s->ptr == NULL) {
		fprintf(stderr, "realloc() failed\n");
		return 0;
	}
	memcpy(s->ptr+s->len, ptr, size*nmemb);
	s->ptr[new_len] = '\0';
	s->len = new_len;

	return size*nmemb;
}

void http_set_uri(CurlWrapper_t* wrapper)
{
	init_string(&(wrapper->str));
	int uri_len = wrapper->url_len + wrapper->host_len + 2;
	wrapper->uri = malloc(uri_len);
	snprintf(wrapper->uri, uri_len, "%s/%s", wrapper->host, wrapper->url);

	curl_easy_setopt(wrapper->curl, CURLOPT_URL, wrapper->uri);
	curl_easy_setopt(wrapper->curl, CURLOPT_WRITEFUNCTION, writefunc);
	curl_easy_setopt(wrapper->curl, CURLOPT_WRITEDATA, &(wrapper->str)) ;
	curl_easy_setopt(wrapper->curl, CURLOPT_CONNECTTIMEOUT, 1);

	if(wrapper->method == CURL_WRAPPER_POST)
	{
		curl_easy_setopt(wrapper->curl, CURLOPT_POST, 1);
	}
	else if(wrapper->method == CURL_WRAPPER_DELETE)
	{
		curl_easy_setopt(wrapper->curl, CURLOPT_CUSTOMREQUEST, "DELETE");
	}
}

void http_set_data(CurlWrapper_t* wrapper)
{
	if(wrapper->method == CURL_WRAPPER_POST || wrapper->method == CURL_WRAPPER_DELETE)
	{
		curl_easy_setopt(wrapper->curl, CURLOPT_POSTFIELDS, wrapper->data);
	}
}

int http_send(CurlWrapper_t* wrapper, void* user_data)
{
	http_set_uri(wrapper);
	http_set_data(wrapper);

	CURLcode rc = curl_easy_perform(wrapper->curl);

	if(rc != 0) curl_easy_strerror(rc);

	if(rc == CURLE_COULDNT_CONNECT)
	{
		printf("Could not connect to %s\n", wrapper->url);
	}

	if(wrapper->cb) wrapper->cb(wrapper->str.ptr, user_data);
	return rc;
}

void http_destroy(CurlWrapper_t* wrapper)
{
	if(wrapper->uri)
		free(wrapper->uri);
	if(wrapper->host)
		free(wrapper->host);

	if ( wrapper->str.ptr == NULL)
		free_string(&(wrapper->str));
	if ( wrapper->curl ) curl_easy_cleanup(wrapper->curl);
	free(wrapper);
}
