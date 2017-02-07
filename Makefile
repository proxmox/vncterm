RELEASE=4.0

PACKAGE=vncterm
# Note: also change version in debian/control and debian/changelog
VERSION=1.3
PACKAGERELEASE=1
ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
CDATE:=$(shell date +%F)

VNCVER=0.9.11
VNCREL=LibVNCServer-${VNCVER}
VNCDIR=libvncserver-${VNCREL}
VNCSRC=${VNCREL}.tar.gz
VNCLIB=${VNCDIR}/libvncserver/.libs/libvncserver.a

TIGERVNCSRC=tigervnc-1.1.0.tgz
#TIGERVNCSRC=tigervnc-1.2.0.tgz

DEB=${PACKAGE}_${VERSION}-${PACKAGERELEASE}_${ARCH}.deb
SNAP=${PACKAGE}-${VERSION}-${CDATE}.tar.gz

KEYSTORE=/home/dietmar/pve2-proxdev/proxmox-dev/comodo-for-java.keystore

all: vncterm

glyphs.h: genfont
	./genfont > glyphs.h.tmp
	mv glyphs.h.tmp glyphs.h

genfont: genfont.c
	gcc -g -O2 -o $@ genfont.c -Wall -D_GNU_SOURCE -lz

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

jar: tigervnc.org
	if test ! -f /usr/share/icedtea-web/plugin.jar; then echo "please install package icedtea-netx-common"; exit 1; fi
	rm -rf tigervnc VncViewer.jar
	rsync -av --exclude .svn --exclude .svnignore  tigervnc.org/ tigervnc
	ln -s ../tigerpatches tigervnc/patches
	cd tigervnc; quilt push -a
	cd tigervnc/java/src/com/tigervnc/vncviewer; make clean; make
	jarsigner -keystore ${KEYSTORE} -signedjar VncViewer.jar  tigervnc/java/src/com/tigervnc/vncviewer/VncViewer.jar "dc475d72-124a-11e4-a53f-005056c00008"

# this is for version 1.2
#	ln -s ../newtigerpatches tigervnc/patches
#	cd tigervnc/java;cmake -G "Unix Makefiles"; make
#	jarsigner -keystore ${KEYSTORE} -signedjar VncViewer.jar  tigervnc/java/VncViewer.jar proxmox

tigervnc.org: ${TIGERVNCSRC}
	rm -rf tigervnc.org
	tar xf ${TIGERVNCSRC}

download:
	rm -rf tigervnc.org
	svn co https://tigervnc.svn.sourceforge.net/svnroot/tigervnc/tags/1_1_0 tigervnc.org 
	tar cf ${TIGERVNCSRC} tigervnc.org

.PHONY: install
install: vncterm vncterm.1 VncViewer.jar
	mkdir -p ${DESTDIR}/usr/share/doc/${PACKAGE}
	mkdir -p ${DESTDIR}/usr/share/man/man1
	mkdir -p ${DESTDIR}/usr/bin
	install -s -m 0755 vncterm ${DESTDIR}/usr/bin
	mkdir -p ${DESTDIR}/usr/share/vncterm/
	install -m 0644 VncViewer.jar ${DESTDIR}/usr/share/vncterm/

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
	rm -rf dest
	mkdir dest
	make DESTDIR=`pwd`/dest install
	install -d -m 0755 dest/DEBIAN
	install -m 0644 debian/control dest/DEBIAN
	echo "Architecture: ${ARCH}" >>dest/DEBIAN/control
	install -m 0644 debian/conffiles dest/DEBIAN
	install -m 0644 copyright dest/usr/share/doc/${PACKAGE}
	install -m 0644 vncterm.1 dest/usr/share/man/man1
	install -m 0644 debian/changelog.Debian dest/usr/share/doc/${PACKAGE}
	gzip --best dest/usr/share/man/*/*
	gzip --best dest/usr/share/doc/${PACKAGE}/changelog.Debian
	dpkg-deb --build dest
	mv dest.deb ${DEB}
	rm -rf dest
	lintian ${DEB}	

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh repoman@repo.proxmox.com upload

.PHONY: clean
clean:
	rm -rf vncterm vncterm.1 vncterm_*.deb tigervnc *~ ${VNCDIR} vncterm-*.tar.gz glyph.h.tmp

.PHONY: distclean
distclean: clean
	rm -rf tigervnc.org

.PHONY: dist
${SNAP} dist: distclean
	rm -rf ../${SNAP}
	cd ..; tar cvzf ${SNAP} --exclude .svn ${PACKAGE}
	mv ../${SNAP} ${SNAP}

.PHONY: uploaddist
uploaddist: ${SNAP}
	scp ${SNAP} pve.proxmox.com:/home/ftp/sources/
