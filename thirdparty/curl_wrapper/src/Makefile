CC = gcc
CURL_DIR=../lib/curl-7.37.1

INC=-I$(CURL_DIR)/include
LIB=-L$(CURL_DIR)/lib/.libs -lcurl

all : test_curl_wrapper  curl_wrapper_o

curl_wrapper_o:
	$(CC) -g -fPIC -m64 -O2 -Wall -lm -D_GNU_SOURCE $(INC) -c curl_wrapper.c $(LIB) 

test_curl_wrapper:
	        $(CC) -g -fPIC -m64 -O2 -Wall -lm -D_GNU_SOURCE $(INC) -o test_curl_wrapper.o curl_wrapper.c test_curl_wrapper.c $(LIB)
clean:
	        rm -rf test_curl_wrapper.o curl_wrapper.o

