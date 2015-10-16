CC ?= gcc
CFLAGS := -O2 $(CFLAGS)
LDFLAGS := -ludev -lmount $(LDFLAGS)
CFDEBUG = -g3 -pedantic -Wall -Wunused-parameter -Wlong-long
CFDEBUG += -Wsign-conversion -Wconversion -Wimplicit-function-declaration

PREFIX ?= /usr/local
ETCPREFIX ?= /etc
BINDIR ?= $(PREFIX)/sbin
LIBDIR ?= $(PREFIX)/lib

EXEC = ldm
SRCS = ldm.c
OBJS = $(SRCS:.c=.o)

all: $(EXEC) doc

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $(EXEC) $(OBJS)

debug: $(EXEC)
debug: CC += $(CFDEBUG)

doc: README.pod
	@pod2man --section=1 --center="ldm Manual" --name "ldm" --release="ldm $(shell git describe)" README.pod > ldm.1

clean:
	$(RM) *.o *.1 ldm

mrproper: clean
	$(RM) $(EXEC)

install-main: ldm doc
	install -D -m 755 ldm $(DESTDIR)$(BINDIR)/ldm
	install -D -m 644 ldm.1 $(DESTDIR)$(PREFIX)/share/man/man1/ldm.1

install-systemd: ldm.service
	install -D -m 644 ldm.service $(DESTDIR)$(LIBDIR)/systemd/system/ldm.service

install-debian-sysv: ldm.service
	install -D -m 644 ldm-sysv-debian $(DESTDIR)$(ETCDIR)/init.d/ldm
	echo 'OPTIONS="-u 1000 -g 1000 -d -p /media"' > $(DESTDIR)$(ETCDIR)/default/ldm

install: all install-main

uninstall:
	$(RM) $(DESTDIR)$(BINDIR)/ldm
	$(RM) $(DESTDIR)$(PREFIX)/share/man/man1/ldm.1
	$(RM) $(DESTDIR)$(SYSTEMDDIR)/system/ldm.service

.PHONY: all debug clean mrproper install install-main install-systemd uninstall
