install_sh = /home/meo/moloch-0.14.2-spsc/install-sh
mkdir_p = mkdir -p --
INSTALL = /usr/bin/install -c
DBDIR = /data/moloch/db


all:

install:
	test -z "$(DBDIR)" || $(mkdir_p) "$(DBDIR)"
	$(INSTALL) daily.sh db.pl elasticsearch.yml.sample runes.sh.sample $(DBDIR)

distclean realclean clean:

