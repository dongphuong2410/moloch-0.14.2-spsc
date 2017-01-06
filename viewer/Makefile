install_sh = /home/meo/moloch-0.14.2-spsc/install-sh
mkdir_p = mkdir -p --
INSTALL = /usr/bin/install -c
VIEWERDIR = /data/moloch/viewer
CP = /bin/cp


all:

install:
	test -z "$(VIEWERDIR)" || $(mkdir_p) "$(VIEWERDIR)"
	/bin/rm -f $(VIEWERDIR)/public/style.css
	$(INSTALL) *.js package.json $(VIEWERDIR)
	$(CP) -pr views public $(VIEWERDIR)
	(cd $(VIEWERDIR) ; npm update)

distclean realclean clean:
	rm -rf node_modules
