PACKAGE=vncterm
# Note: also change version in debian/control and debian/changelog
VERSION=1.4
PACKAGERELEASE=2
ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
GITVERSION:=$(shell cat .git/refs/heads/master)
CDATE:=$(shell date +%F)

VNCVER=0.9.11
VNCREL=LibVNCServer-${VNCVER}
VNCDIR=libvncserver-${VNCREL}
VNCSRC=${VNCREL}.tar.gz
VNCLIB=${VNCDIR}/libvncserver/.libs/libvncserver.a

DEB=${PACKAGE}_${VERSION}-${PACKAGERELEASE}_${ARCH}.deb
SNAP=${PACKAGE}-${VERSION}-${CDATE}.tar.gz

all: vncterm

glyphs.h: genfont
	./genfont > glyphs.h.tmp
	mv glyphs.h.tmp glyphs.h

genfont: genfont.c
	gcc -g -O2 -o $@ genfont.c -Wall -D_GNU_SOURCE -lz

font.data: genfont2
	./genfont2 -o font.data.tmp -i /usr/share/unifont/unifont.hex
	mv font.data.tmp font.data

genfont2: genfont2.c
	gcc -g -O2 -o $@ genfont2.c -Wall -Wextra -D_GNU_SOURCE -lz

.PHONY: vnc
${VNCLIB} vnc: ${VNCSRC}
	rm -rf ${VNCDIR}
	tar xf ${VNCSRC}
	ln -s ../vncpatches ${VNCDIR}/patches
	cd ${VNCDIR}; quilt push -a
	cd ${VNCDIR}; ./autogen.sh --without-ssl --without-websockets --without-tightvnc-filetransfer;
	cd ${VNCDIR}; make

vncterm: vncterm.c glyphs.h ${VNCLIB}
	gcc -O2 -g -o $@ vncterm.c -Wall -Wno-deprecated-declarations -D_GNU_SOURCE -I ${VNCDIR} ${VNCLIB} -lnsl -lpthread -lz -ljpeg -lutil -lgnutls -lpng


.PHONY: install
install: vncterm vncterm.1
	mkdir -p ${DESTDIR}/usr/share/doc/${PACKAGE}
	install -m 0644 copyright ${DESTDIR}/usr/share/doc/${PACKAGE}
	mkdir -p ${DESTDIR}/usr/share/man/man1
	install -m 0644 vncterm.1 ${DESTDIR}/usr/share/man/man1
	mkdir -p ${DESTDIR}/usr/bin
	install -s -m 0755 vncterm ${DESTDIR}/usr/bin

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}

vncterm.1: vncterm.pod
	rm -f $@
	pod2man -n $< -s 1 -r ${VERSION} <$< >$@

.PHONY: deb
deb: $(DEB)
${DEB}:
	make clean
	rsync -a . --exclude build build
	echo "Architecture: ${ARCH}" >> build/debian/control
	echo "git clone git://git.proxmox.com/git/vncterm.git\\ngit checkout ${GIVERSION}" > build/debian/SOURCE
	cd build; dpkg-buildpackage -rfakeroot -b -us -uc
	lintian ${DEB}	

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh -X repoman@repo.proxmox.com -- upload --product pmg,pve --dist stretch

.PHONY: clean
clean:
	rm -rf vncterm vncterm.1 vncterm_*.deb genfont genfont2 *~ ${VNCDIR} vncterm-*.tar.gz glyph.h.tmp build *.changes font.data.tmp font.data

.PHONY: distclean
distclean: clean

.PHONY: dist
${SNAP} dist: distclean
	rm -rf ../${SNAP}
	cd ..; tar cvzf ${SNAP} --exclude .svn ${PACKAGE}
	mv ../${SNAP} ${SNAP}

.PHONY: uploaddist
uploaddist: ${SNAP}
	scp ${SNAP} pve.proxmox.com:/home/ftp/sources/
