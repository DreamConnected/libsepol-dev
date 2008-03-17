# Installation directories.
PREFIX ?= /usr
INCDIR ?= $(PREFIX)/include
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib

VERSION = $(shell cat ../VERSION)
LIBVERSION = 1

LIBA=libsepol.a 
TARGET=libsepol.so
LIBPC=libsepol.pc
LIBSO=$(TARGET).$(LIBVERSION)
OBJS= $(patsubst %.c,%.o,$(wildcard *.c))
LOBJS= $(patsubst %.c,%.lo,$(wildcard *.c))
CFLAGS ?= -Werror -Wall -W -Wundef -Wmissing-noreturn -Wmissing-format-attribute
override CFLAGS += -I. -I../include -D_GNU_SOURCE

all: $(LIBA) $(LIBSO) $(LIBPC)

$(LIBA):  $(OBJS)
	$(AR) rcs $@ $^
	ranlib $@

$(LIBSO): $(LOBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^ -Wl,-soname,$(LIBSO),--version-script=libsepol.map,-z,defs
	ln -sf $@ $(TARGET) 

$(LIBPC): $(LIBPC).in
	sed -e 's/@VERSION@/$(VERSION)/; s:@prefix@:$(PREFIX):; s:@libdir@:$(LIBDIR):; s:@includedir@:$(INCDIR):' < $< > $@

%.o:  %.c 
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

%.lo:  %.c
	$(CC) $(CFLAGS) -fPIC -DSHARED -c -o $@ $<

install: all
	test -d $(DESTDIR)$(LIBDIR) || install -m 755 -d $(DESTDIR)$(LIBDIR)
	install -m 644 $(LIBA) $(DESTDIR)$(LIBDIR)
	test -d $(DESTDIR)$(LIBDIR)/pkgconfig || install -m 755 -d $(DESTDIR)$(LIBDIR)/pkgconfig
	install -m 644 $(LIBPC) $(DESTDIR)$(LIBDIR)/pkgconfig
	test -d $(SHLIBDIR) || install -m 755 -d $(SHLIBDIR)
	install -m 755 $(LIBSO) $(SHLIBDIR)
	cd $(DESTDIR)$(LIBDIR) && ln -sf ../../`basename $(SHLIBDIR)`/$(LIBSO) $(TARGET)

relabel:
	/sbin/restorecon $(SHLIBDIR)/$(LIBSO)

clean: 
	-rm -f $(OBJS) $(LOBJS) $(LIBA) $(LIBSO) $(TARGET) $(LIBPC)

indent:
	../../scripts/Lindent $(wildcard *.[ch])

