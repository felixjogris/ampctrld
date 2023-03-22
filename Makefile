CC ?= cc
CFLAGS = -W -Wall -O3 -pipe
LDFLAGS = -s

.PHONY:	clean install

ampctrld:	ampctrld.o
	$(CC) $(LDFLAGS) -o $@ ampctrld.o

ampctrld.o:	ampctrld.c rootpage_html.h favicon_ico.h
	$(CC) $(CFLAGS) -c -o $@ ampctrld.c

rootpage_html.h:	rootpage.html bin2c.pl
	perl bin2c.pl rootpage.html

favicon_ico.h:	favicon.ico bin2c.pl
	perl bin2c.pl favicon.ico

install:	ampctrld ampctrld.sh
	install -d /usr/local/sbin /usr/local/etc/rc.d
	install ampctrld /usr/local/sbin/
	install ampctrld.sh /usr/local/etc/rc.d/ampctrld
	-echo "Don't forget to enable ampctrld, e.g. by 'sysrc ampctrld_enable=YES'"

clean: ;	-rm -v ampctrld *.o
