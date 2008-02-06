############################ -*- Mode: Makefile -*- ###########################
## local.mk --- 
## Author           : Manoj Srivastava ( srivasta@glaurung.green-gryphon.com ) 
## Created On       : Sat Nov 15 10:42:10 2003
## Created On Node  : glaurung.green-gryphon.com
## Last Modified By : Manoj Srivastava
## Last Modified On : Fri Oct 20 14:24:16 2006
## Last Machine Used: glaurung.internal.golden-gryphon.com
## Update Count     : 22
## Status           : Unknown, Use with caution!
## HISTORY          : 
## Description      : 
## 
## arch-tag: b07b1015-30ba-4b46-915f-78c776a808f4
## 
###############################################################################

testdir:
	$(testdir)



BUILD/libsepol1:: build/libsepol1
INST/libsepol1:: install/libsepol1
BIN/libsepol1:: binary/libsepol1


INST/libsepol1-dev:: install/libsepol1-dev
BIN/libsepol1-dev:: binary/libsepol1-dev


INST/sepol-utils:: install/sepol-utils
BIN/sepol-utils:: binary/sepol-utils


CLN-common::
	$(REASON)
	-test ! -f Makefile || $(MAKE) clean

CLEAN/libsepol1::
	-rm -rf $(TMPTOP)

CLEAN/libsepol1-dev::
	-rm -rf $(TMPTOP)

CLEAN/sepol-utils::
	-rm -rf $(TMPTOP)


build/libsepol1:
	$(checkdir)
	$(REASON)
	$(MAKE) CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)"
	touch stamp-build-libsepol1

STAMPS_TO_CLEAN += stamp-build-libsepol1


install/libsepol1: testroot
	$(checkdir)
	$(REASON)
	rm -rf		    $(TMPTOP)
	$(make_directory)   $(TMPTOP)
	$(make_directory)   $(DOCDIR)
	$(make_directory)   $(LIBDIR)
	$(make_directory)   $(TMPTOP)/DEBIAN
	$(install_file)	    debian/shlibs	     $(TMPTOP)/DEBIAN
	$(MAKE)		    DESTDIR=$(TMPTOP) -C src install
	rm -f		    $(LIBDIR)/libsepol.a
	rm -f		    $(LIBDIR)/libsepol.so
	test ! -e           $(LIBDIR)/libsepol.pc || rm -f $(LIBDIR)/libsepol.pc
	rm -rf              $(TMPTOP)/usr/lib
	chmod 0644          $(LIBDIR)/libsepol.so.1
	$(install_file)	    debian/changelog	     $(DOCDIR)/changelog.Debian
	$(install_file)	    ChangeLog		     $(DOCDIR)/changelog
	gzip -9fqr	    $(DOCDIR)/
# Make sure the copyright file is not compressed
	$(install_file)	     debian/copyright	     $(DOCDIR)/copyright
ifeq (,$(findstring nostrip,$(DEB_BUILD_OPTIONS)))
	find $(TMPTOP) -type f | while read i; do					 \
	  if file -b $$i | egrep -q "^ELF.*shared object"; then				 \
	    strip --strip-unneeded --remove-section=.comment --remove-section=.note $$i; \
	  fi;										 \
	done
endif

install/libsepol1-dev: testroot
	$(checkdir)
	$(REASON)
	rm -rf		    $(TMPTOP)
	$(make_directory)   $(TMPTOP)
	$(make_directory)   $(DOCDIR)
	$(make_directory)   $(LIBDIR)
	$(make_directory)   $(TMPTOP)/usr/lib
	$(make_directory)   $(INCDIR)
	$(make_directory)   $(MAN3DIR)
	$(make_directory)   $(MAN8DIR)
	$(MAKE)		    DESTDIR=$(TMPTOP) -C man install
	rm -rf		    $(MAN8DIR)
	$(MAKE)		    DESTDIR=$(TMPTOP) -C include install
	$(MAKE)		    DESTDIR=$(TMPTOP) -C src install
	rm -rf		    $(LIBDIR)
	rm -f		    $(TMPTOP)/usr/lib/libsepol.so
	ln -s               /lib/libsepol.so.1       $(TMPTOP)/usr/lib/libsepol.so
	$(install_file)	    debian/changelog	     $(DOCDIR)/changelog.Debian
	$(install_file)	    ChangeLog		     $(DOCDIR)/changelog
	gzip -9fqr	    $(DOCDIR)/
	gzip -9fqr	    $(MANDIR)/
# Make sure the copyright file is not compressed
	$(install_file)	     debian/copyright	     $(DOCDIR)/copyright
ifeq (,$(findstring nostrip,$(DEB_BUILD_OPTIONS)))
	find $(TMPTOP) -type f | while read i; do					 \
	  if file -b $$i | egrep -q "^ELF.*shared object"; then				 \
	    strip --strip-unneeded --remove-section=.comment --remove-section=.note $$i; \
	  fi;										 \
	done
endif

install/sepol-utils: testroot
	$(checkdir)
	$(REASON)
	rm -rf		    $(TMPTOP)
	$(make_directory)   $(TMPTOP)
	$(make_directory)   $(DOCDIR)
	$(make_directory)   $(MAN3DIR)
	$(make_directory)   $(MAN8DIR)
	$(MAKE)             DESTDIR=$(TMPTOP) -C man install
	rm -rf              $(MAN3DIR)
	$(MAKE) DESTDIR=$(TMPTOP) -C utils install
	$(install_file)	     debian/changelog	     $(DOCDIR)/changelog.Debian
	$(install_file)	    ChangeLog		     $(DOCDIR)/changelog
	gzip -9fqr	    $(DOCDIR)/
	gzip -9fqr	    $(MANDIR)/
# Make sure the copyright file is not compressed
	$(install_file)	     debian/copyright	     $(DOCDIR)/copyright
ifeq (,$(findstring nostrip,$(DEB_BUILD_OPTIONS)))
	find $(TMPTOP) -type f | while read i; do				    \
	  if file -b $$i | egrep -q "^ELF.*executable"; then			    \
	    strip --strip-all --remove-section=.comment --remove-section=.note $$i; \
	  fi;									    \
	done
endif


binary/libsepol1: testroot
	$(checkdir)
	$(REASON)
	$(install_script)    debian/postrm	     $(TMPTOP)/DEBIAN/postrm
	$(install_script)    debian/postinst	     $(TMPTOP)/DEBIAN/postinst
	k=`find $(TMPTOP) -type f | ( while read i; do		 \
	    if file -b $$i | egrep -q "^ELF.*shared object"; then	 \
	      j="$$j $$i";					 \
	    fi;							 \
	   done; echo $$j; )`; if [ -n "$$k" ]; then dpkg-shlibdeps $$k; fi
	dpkg-gencontrol	     -p$(package) -isp	     -P$(TMPTOP)
	$(create_md5sum)     $(TMPTOP)
	chown -R root:root   $(TMPTOP)
	chmod -R u+w,go=rX   $(TMPTOP)
	dpkg --build	     $(TMPTOP) ..

binary/libsepol1-dev: testroot
	$(checkdir)
	$(REASON)
	$(make_directory)    $(TMPTOP)/DEBIAN
	dpkg-gencontrol	     -p$(package) -isp	     -P$(TMPTOP)
	$(create_md5sum)     $(TMPTOP)
	chown -R root:root   $(TMPTOP)
	chmod -R u+w,go=rX   $(TMPTOP)
	dpkg --build	     $(TMPTOP) ..

binary/sepol-utils: testroot
	$(checkdir)
	$(REASON)
	$(make_directory)    $(TMPTOP)/DEBIAN
	k=`find $(TMPTOP) -type f | ( while read i; do		 \
	    if file -b $$i | egrep -q "^ELF.*executable"; then	 \
	      j="$$j $$i";					 \
	    fi;							 \
	   done; echo $$j; )`; dpkg-shlibdeps -Ldebian/shlibs -Tsubstvars.utils $$k
	dpkg-gencontrol	     -Tsubstvars.utils -p$(package) -isp    -P$(TMPTOP)
	$(create_md5sum)     $(TMPTOP)
	chown -R root:root   $(TMPTOP)
	chmod -R u+w,go=rX   $(TMPTOP)
	dpkg --build	     $(TMPTOP) ..
