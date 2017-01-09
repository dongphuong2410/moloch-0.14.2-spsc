INCLUDE_PCAP  = -I/home/meo/moloch-0.14.2-spsc/thirdparty/libpcap-1.7.4
INCLUDE_RIPMIME  = -I/home/meo/moloch-0.14.2-spsc/thirdparty/ripmime
INCLUDE_P0F  = -I/home/meo/moloch-0.14.2-spsc/thirdparty/p0f
INCLUDE_CURL_WRAPPER = -I/home/meo/moloch-0.14.2-spsc/thirdparty/curl_wrapper/src

INCLUDE_OTHER = -I.. -I../thirdparty \
                -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/glib -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4 -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gmodule -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gobject
SRC_OTHER = ../thirdparty/email_util.c

LIB_RIPMIME = /home/meo/moloch-0.14.2-spsc/thirdparty/ripmime/libripmime.a
LDFLAGS=-lzmq -lripmime -L/home/meo/moloch-0.14.2-spsc/thirdparty/ripmime/

install_sh = /home/meo/moloch-0.14.2-spsc/install-sh
mkdir_p = mkdir -p --
INSTALL = /usr/bin/install -c
PARSERSDIR = /data/moloch/parsers

SRCS=$(wildcard *.c)
SOS=$(SRCS:.c=.so)

%.so : %.c ../moloch.h ../hash.h ../dll.h
	$(CC) $(TEST_CFLAGS) --shared -o $@ -O2 -ggdb -Wall -Wextra -D_GNU_SOURCE -fPIC $(INCLUDE_PCAP) $(INCLUDE_RIPMIME) $(INCLUDE_CURL_WRAPPER) $(INCLUDE_P0F) $(INCLUDE_OTHER) $< $(SRC_OTHER) $(LDFLAGS)

all:$(SOS)

install:
	test -z "$(PARSERSDIR)" || $(mkdir_p) "$(PARSERSDIR)"
	$(INSTALL) *.so *.jade $(PARSERSDIR)

distclean realclean clean:
	rm -f *.o *.so

