INSTALL_DIR   = @INSTALL_DIR@

CC            = gcc

INCLUDE_PCAP  = -I/home/meo/moloch-0.14.2-spsc/thirdparty/libpcap-1.7.4
INCLUDE_RIPMIME   = -I/home/meo/moloch-0.14.2-spsc/thirdparty/ripmime
INCLUDE_CURL_WRAPPER = -I/home/meo/moloch-0.14.2-spsc/thirdparty/curl_wrapper/src
INCLUDE_SNF   = -I/opt/snf/include/

INCLUDE_OTHER = -Ithirdparty \
                -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/glib -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4 -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gmodule -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gobject \
	        -I/home/meo/moloch-0.14.2-spsc/thirdparty/yara-1.7/libyara \
	        -I/home/meo/moloch-0.14.2-spsc/thirdparty/GeoIP-1.6.0/libGeoIP \
	        -I/home/meo/moloch-0.14.2-spsc/thirdparty/curl-7.42.1/include


LIB_PCAP      = /home/meo/moloch-0.14.2-spsc/thirdparty/libpcap-1.7.4/libpcap.a
LIB_RIPMIME       = /home/meo/moloch-0.14.2-spsc/thirdparty/ripmime/libripmime.a
LIB_SNF       = /opt/snf/lib/*.so
LIB_CURL_WRAPPER = /home/meo/moloch-0.14.2-spsc/thirdparty/curl_wrapper/src/curl_wrapper.o
LIB_OTHER     = /home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/glib/.libs/libglib-2.0.a /home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gio/.libs/libgio-2.0.a /home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gobject/.libs/libgobject-2.0.a /home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gthread/.libs/libgthread-2.0.a /home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gmodule/.libs/libgmodule-2.0.a /home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/glib/.libs/libglib-2.0.a \
	        /home/meo/moloch-0.14.2-spsc/thirdparty/yara-1.7/libyara/.libs/libyara.a \
	        /home/meo/moloch-0.14.2-spsc/thirdparty/GeoIP-1.6.0/libGeoIP/.libs/libGeoIP.a \
	        /home/meo/moloch-0.14.2-spsc/thirdparty/curl-7.42.1/lib/.libs/libcurl.a \
                -lrt -lmagic -luuid -lpcre  \
	        thirdparty/http_parser.o \
		thirdparty/picohttpparser.o \
	        thirdparty/js0n.o \
	        thirdparty/patricia.o \
	        thirdparty/common.o \
	        thirdparty/file_manager.o \
	        thirdparty/multipart_parser.o \
		-ldl -lpthread -lssl -lcrypto -lzmq

C_FILES         = main.c db.c yara.c http.c config.c parsers.c plugins.c field.c trie.c writers.c writer-inplace.c writer-disk.c writer-null.c writer-simple.c readers.c reader-libpcap-file.c reader-libpcap.c packet.c session.c fingerprint.c
O_FILES         = $(C_FILES:.c=.o)

INSTALL         = /usr/bin/install -c
bindir          = /data/moloch/bin

C_FILES		+= spsc_ring.c
ADDON_CFLAGS    = -msse4.2
ADDON_CFLAGS    += -DUSE_ONE_SSID
ADDON_CFLAGS    += -DUSE_SPSC_RING
ADDON_CFLAGS    += -DUSE_MTCP_HASH
ADDON_CFLAGS    += -DUSE_SCHED_AFFINITY

TEST_CFLAGS=
export TEST_CFLAGS

OBJECTS=thirdparty/js0n.o thirdparty/http_parser.o thirdparty/patricia.o thirdparty/picohttpparser.o thirdparty/file_manager.o thirdparty/multipart_parser.o thirdparty/common.o
all:$(OBJECTS)
	$(CC) -fPIC -O2 -ggdb -Wall -Wextra -D_GNU_SOURCE $(TEST_CFLAGS) $(ADDON_CFLAGS) -c $(C_FILES) \
	    $(INCLUDE_PCAP) \
	    $(INCLUDE_RIPMIME) \
	    $(INCLUDE_CURL_WRAPPER) \
	    $(INCLUDE_OTHER) 
	$(CC) -rdynamic -ggdb $(O_FILES) -o moloch-capture \
            -u g_checksum_update -u g_hmac_update \
	    $(LIB_PCAP) \
	    $(LIB_CURL_WRAPPER) \
	    $(LIB_RIPMIME) \
	    $(LIB_OTHER) \
	    -lm -lresolv -lffi -lz
	(cd parsers; $(MAKE))
	(cd plugins; $(MAKE))

testmode: TEST_CFLAGS += -DTESTMODE -ggdb -O0
testmode: all

snf:$(OBJECTS)
	gcc -ggdb -Wall -Wextra -D_GNU_SOURCE $(ADDON_CFLAGS) -c $(C_FILES) \
	    $(INCLUDE_SNF) -DSNF \
	    $(INCLUDE_OTHER) 
	g++ -ggdb $(O_FILES) -o moloch-capture \
            -u g_checksum_update -u g_hmac_update \
	    $(LIB_SNF) \
	    $(LIB_OTHER) \
	    -lrt -lm -lpcre -lresolv -luuid -lmagic -lffi -lz

$(OBJECTS): %.o: %.c
	$(CC) $(TEST_CFLAGS) -c $< -o $@

install: installdirs
	$(INSTALL) moloch-capture $(bindir)/moloch-capture

installdirs:
	$(INSTALL) -d $(bindir)
	(cd parsers; $(MAKE) install)
	(cd plugins; $(MAKE) install)

distclean realclean clean:
	rm -f parsers/*.so thirdparty/*.o *.o moloch-capture

