CC            = gcc

INCLUDE_PCAP  = -I/home/meo/moloch-0.14.2-spsc/thirdparty/libpcap-1.7.4

INCLUDE_OTHER = -I../../capture -I../../capture/thirdparty \
                -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/glib -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4 -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gmodule -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gobject

all:
	gcc --shared -o test.so -O2 -ggdb -Wall -Wextra -D_GNU_SOURCE -fPIC $(INCLUDE_OTHER) $(INCLUDE_PCAP) test.c
