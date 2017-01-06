#include "curl_wrapper.h"
#include <unistd.h>

void test_cb(char* ptr, void* user_data)
{
	printf("\n ptr : [%s]\n", ptr);
}

int test_curl_get()
{
	CurlWrapper_t* curl = http_init("127.0.0.1:9200");

	http_param_set(curl, CURL_WRAPPER_GET, "", NULL, NULL); 
	http_send(curl, NULL);

	http_destroy(curl);
	
	return 1;
}

int test_curl_post()
{
	while(1)
	{
	CurlWrapper_t* curl = http_init("127.0.0.1:9200");

	char* url = "/sessions*/_search?size=10000&pretty=true";
	char* send_data = "{"
		"\"query\": {"
		"\"range\": {"
		"\"fpd\": {"
		"\"from\": 1015152416645,"
		"\"to\": 1515159999999"
		"}"
		"}"
		"}"
		"}\r\n";

	http_param_set(curl, CURL_WRAPPER_POST, url, send_data, test_cb); 
	http_send(curl, NULL);

	http_reuse(curl);

	http_param_set(curl, CURL_WRAPPER_POST, url, send_data, test_cb); 
	http_send(curl, NULL);

	http_reuse(curl);

	http_param_set(curl, CURL_WRAPPER_POST, url, send_data, test_cb); 
	http_send(curl, NULL);


	http_reuse(curl);

	http_param_set(curl, CURL_WRAPPER_POST, url, send_data, test_cb); 
	http_send(curl, NULL);

	http_destroy(curl);
	}
	
	return 1;
}

int main()
{
	test_curl_get();
	test_curl_post();
	return 1;
}
