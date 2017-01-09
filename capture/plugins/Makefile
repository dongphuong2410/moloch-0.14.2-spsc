CC            = gcc

INCLUDE_PCAP  = -I/home/meo/moloch-0.14.2-spsc/thirdparty/libpcap-1.7.4
INCLUDE_P0F  = -I/home/meo/moloch-0.14.2-spsc/thirdparty/p0f
INCLUDE_CURL_WRAPPER = -I/home/meo/moloch-0.14.2-spsc/thirdparty/curl_wrapper/src

INCLUDE_OTHER = -I.. -I../thirdparty \
                -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/glib -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4 -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gmodule -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gobject

install_sh = /home/meo/moloch-0.14.2-spsc/install-sh
mkdir_p = mkdir -p --
INSTALL = /usr/bin/install -c
PLUGINDIR = /data/moloch/plugins
WISEDIR = /data/moloch/wiseService

SRCS=$(wildcard *.c)
SOS=$(SRCS:.c=.so)

%.so : %.c ../moloch.h ../hash.h ../dll.h
	$(CC) --shared -o $@ -O2 -ggdb -Wall -Wextra -D_GNU_SOURCE -fPIC $(INCLUDE_PCAP) $(INCLUDE_P0F) $(INCLUDE_CURL_WRAPPER) $(INCLUDE_OTHER) $<

all:$(SOS)

install:
	test -z "$(PLUGINDIR)" || $(mkdir_p) "$(PLUGINDIR)"
	$(INSTALL) *.so *.jade *.js $(PLUGINDIR)
	test -z "$(WISEDIR)" || $(mkdir_p) "$(WISEDIR)"
	$(INSTALL) wiseService/*.js wiseService/wiseService.ini.sample wiseService/package.json $(WISEDIR)
	(cd $(WISEDIR) ; npm update)

distclean realclean clean:
	rm -f *.o *.so
