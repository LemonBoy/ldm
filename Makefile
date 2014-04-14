EXEC = ldm
VERSION = $(shell grep 'VERSION_STR ' ldm.c | cut -d'"' -f2)

SRCS = ldm.c
OBJS = $(SRCS:.c=.o)

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SYSTEMDDIR ?= $(PREFIX)/lib/systemd

CC ?= gcc
CFLAGS := -O2 $(CFLAGS)
LDFLAGS := -ludev -lmount $(LDFLAGS)
CFDEBUG = -g3 -pedantic -Wall -Wunused-parameter -Wlong-long
CFDEBUG += -Wsign-conversion -Wconversion -Wimplicit-function-declaration

all: $(EXEC) doc

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $(EXEC) $(OBJS)

debug: $(EXEC)
debug: CC += $(CFDEBUG)

doc: README.pod
	@pod2man --section=1 --center="ldm Manual" --name "ldm" --release="ldm $(VERSION)" README.pod > ldm.1

clean:
	$(RM) *.o *.1 ldm

mrproper: clean
	$(RM) $(EXEC)

install-main: ldm doc
	install -D -m 755 ldm $(DESTDIR)$(BINDIR)/ldm
	install -D -m 644 ldm.1 $(DESTDIR)$(PREFIX)/share/man/man1/ldm.1

install-systemd: ldm.service
	install -D -m 644 ldm.service $(DESTDIR)$(SYSTEMDDIR)/system/ldm.service

install: all install-main install-systemd

uninstall:
	$(RM) $(DESTDIR)$(BINDIR)/ldm
	$(RM) $(DESTDIR)$(PREFIX)/share/man/man1/ldm.1
	$(RM) $(DESTDIR)$(SYSTEMDDIR)/system/ldm.service

.PHONY: all debug clean mrproper install install-main install-systemd uninstall
