CC ?= cc
CFLAGS = -W -Wall -O3 -pipe
LDFLAGS = -s

.PHONY:	clean install

ampctrld:	ampctrld.o
	$(CC) $(LDFLAGS) -o $@ ampctrld.o

ampctrld.o:	ampctrld.c rootpage.h favicon.h
	$(CC) $(CFLAGS) -c -o $@ ampctrld.c

rootpage.h:	rootpage.html bin2c.pl
	perl bin2c.pl rootpage.html "text/html; charset=utf8" rootpage

favicon.h:	favicon.ico bin2c.pl
	perl bin2c.pl favicon.ico "image/x-icon" favicon

install:	ampctrld ampctrld.sh
	install -d /usr/local/sbin /usr/local/etc/rc.d
	install ampctrld /usr/local/sbin/
	install ampctrld.sh /usr/local/etc/rc.d/ampctrld
	-echo "Don't forget to enable ampctrld, e.g. by 'sysrc ampctrld_enable=YES'"

clean: ;	-rm -v ampctrld *.o
