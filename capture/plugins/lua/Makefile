CC            = gcc

INCLUDE_OTHER = -I../.. -I../../thirdparty \
                -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/glib -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4 -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gmodule -I/home/meo/moloch-0.14.2-spsc/thirdparty/glib-2.47.4/gobject

install_sh = /home/meo/moloch-0.14.2-spsc/install-sh
mkdir_p = mkdir -p --
INSTALL = /usr/bin/install -c
PLUGINDIR = /data/moloch/plugins
LUA_CFLAGS = 
LUA_LIBS = -llua

SRCS=$(wildcard *.c)

../lua.so : $(SRCS) ../../moloch.h ../../hash.h ../../dll.h
	$(CC) --shared -o $@ -O2 -ggdb -Wall -Wextra -D_GNU_SOURCE -fPIC $(INCLUDE_OTHER) $(LUA_CFLAGS) $(SRCS) $(LUA_LIBS)

all:$(SOS)

distclean realclean clean:
	rm -f *.o *.so
