CC ?= cc
CFLAGS = -W -Wall -O3 -pipe
LDFLAGS = -s

ifdef USE_SYSTEMD
  CFLAGS += -DUSE_SYSTEMD
endif
ifdef BUILD_ROOT
  CFLAGS += -I$(BUILD_ROOT)/usr/include
  LDFLAGS += -L$(BUILD_ROOT)/usr/lib
endif

.PHONY:	clean install package

ampctrld:	ampctrld.o
	$(CC) $(LDFLAGS) -o $@ ampctrld.o

ampctrld.o:	ampctrld.c rootpage_html.h favicon_ico.h
	$(CC) $(CFLAGS) -c -o $@ ampctrld.c

rootpage_html.h:	rootpage.html bin2c.pl
	perl bin2c.pl rootpage.html

favicon_ico.h:	favicon.ico bin2c.pl
	perl bin2c.pl favicon.ico

install:	ampctrld ampctrld.service ampctrld.openrc
	install -d /usr/local/sbin
	install ampctrld /usr/local/sbin/
	install -m 0644 ampctrld.service /lib/systemd/system/ || install ampctrld.openrc /etc/init.d/ampctrld

package:	clean
	$(eval VERSION=$(shell awk -F'"' '{if(/define\s+AMPCTRLD_VERSION/){print $$2}}' ampctrld.c))
	$(eval TMPDIR=$(shell mktemp -d))
	mkdir $(TMPDIR)/ampctrld-$(VERSION)
	cp -aiv * $(TMPDIR)/ampctrld-$(VERSION)/
	tar -C $(TMPDIR) -cvjf $(TMPDIR)/ampctrld-$(VERSION).tar.bz2 ampctrld-$(VERSION)
	sed -i 's/PKG_VERSION:=.*/PKG_VERSION:=$(VERSION)/; '\
	's/PKG_SOURCE:=.*/PKG_SOURCE:=ampctrld-$(VERSION).tar.bz2/; '\
	's/PKG_HASH:=.*/PKG_HASH:='\
	`sha256sum $(TMPDIR)/ampctrld-$(VERSION).tar.bz2 | awk '{print $$1}'`\
	'/' openwrt/Makefile
	sha256sum $(TMPDIR)/ampctrld-$(VERSION).tar.bz2

clean: ;	-rm -v ampctrld *.o
