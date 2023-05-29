include /usr/share/dpkg/pkg-info.mk
include /usr/share/dpkg/architecture.mk

PACKAGE=vncterm
GITVERSION:=$(shell cat .git/refs/heads/master)

VNCVER=0.9.14
VNCREL=LibVNCServer-$(VNCVER)
VNCDIR=libvncserver-$(VNCREL)
VNCSRC=$(VNCREL).tar.gz
VNCLIB=$(VNCDIR)/libvncserver.a

DEB=$(PACKAGE)_$(DEB_VERSION_UPSTREAM_REVISION)_$(DEB_BUILD_ARCH).deb
DBG_DEB=$(PACKAGE)-dbgysm_$(DEB_VERSION_UPSTREAM_REVISION)_$(DEB_BUILD_ARCH).deb

CPPFLAGS += -O2 -g -Wall -Wno-deprecated-declarations -D_GNU_SOURCE -I $(VNCDIR)

VNC_LIBS := -lnsl -lpthread -lz -ljpeg -lutil -lgnutls -lpng

all: vncterm

font.data: genfont2
	./genfont2 -o font.data.tmp -i /usr/share/unifont/unifont.hex
	mv font.data.tmp font.data

genfont2: genfont2.c
	gcc -g -O2 -o $@ genfont2.c -Wall -Wextra -D_GNU_SOURCE -lz

.PHONY: vnc
vnc: $(VNCLIB)
$(VNCLIB): $(VNCSRC)
	rm -rf $(VNCDIR)
	tar xf $(VNCSRC)
	ln -s ../vncpatches $(VNCDIR)/patches
	cd $(VNCDIR); quilt push -a
	cd $(VNCDIR); cmake -D WITH_GNUTLS=OFF -D WITH_OPENSSL=OFF -D WITH_WEBSOCKETS=OFF -D WITH_SYSTEMD=OFF -D WITH_TIGHTVNC_FILETRANSFER=OFF -D WITH_GCRYPT=OFF -D WITH_LZO=OFF -D BUILD_SHARED_LIBS=OFF .; cmake --build .

vncterm: vncterm.c wchardata.c $(VNCLIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(VNC_LIBS)

wchardata.c:
	cp /usr/share/unifont/$@ $@

.PHONY: install
install: vncterm vncterm.1 font.data
	mkdir -p $(DESTDIR)/usr/share/doc/$(PACKAGE)
	install -m 0644 copyright $(DESTDIR)/usr/share/doc/$(PACKAGE)
	mkdir -p $(DESTDIR)/usr/share/$(PACKAGE)
	install -m 0644 font.data $(DESTDIR)/usr/share/$(PACKAGE)
	mkdir -p $(DESTDIR)/usr/share/man/man1
	install -m 0644 vncterm.1 $(DESTDIR)/usr/share/man/man1
	mkdir -p $(DESTDIR)/usr/bin
	install -m 0755 vncterm $(DESTDIR)/usr/bin

.PHONY: dinstall
dinstall: $(DEB)
	dpkg -i $(DEB)

vncterm.1: vncterm.pod
	rm -f $@
	pod2man -n $< -s 1 -r $(DEB_VERSION_UPSTREAM) <$< >$@

.PHONY: deb
deb: $(DEB)
$(DEB):
	$(MAKE) clean
	rsync -a . --exclude build build
	echo "git clone git://git.proxmox.com/git/vncterm.git\\ngit checkout $(GIVERSION)" > build/debian/SOURCE
	cd build; dpkg-buildpackage -rfakeroot -b -us -uc
	lintian $(DEB)

.PHONY: upload
upload: $(DEB)
	tar cf - $(DEB) $(DBG_DEB) | ssh -X repoman@repo.proxmox.com -- upload --product pve --dist bullseye

.PHONY: clean
clean:
	rm -rf vncterm vncterm.1 vncterm_*.deb genfont genfont2 *~ $(VNCDIR) vncterm-*.tar.gz glyph.h.tmp build *.changes wchardata.c font.data.tmp font.data *.buildinfo

.PHONY: distclean
distclean: clean
