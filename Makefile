CC ?= gcc
CFLAGS := -O2 $(CFLAGS)
LDFLAGS := -ludev -lmount $(LDFLAGS)
CFDEBUG = -g3 -pedantic -Wall -Wunused-parameter -Wlong-long
CFDEBUG += -Wsign-conversion -Wconversion -Wimplicit-function-declaration

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
ETCDIR ?= $(PREFIX)/etc
SYSTEMDDIR ?= $(PREFIX)/lib/systemd

EXEC = ldm
SRCS = ldm.c
OBJS = $(SRCS:.c=.o)

all: $(EXEC)

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $(EXEC) $(OBJS)

debug: $(EXEC)
debug: CC += $(CFDEBUG)

clean:
	$(RM) *.o ldm

mrproper: clean
	$(RM) $(EXEC)

install-main: ldm
	install -D -m 755 ldm $(DESTDIR)$(BINDIR)/ldm

install-config: ldm.conf
	install -D -m 644 ldm.conf $(DESTDIR)$(ETCDIR)/ldm.conf

install-systemd: ldm.service
	install -D -m 644 ldm.service $(DESTDIR)$(SYSTEMDDIR)/system/ldm.service

install: all install-main install-config install-systemd

uninstall:
	$(RM) $(DESTDIR)$(BINDIR)/ldm
	$(RM) $(DESTDIR)$(ETCDIR)/ldm.conf
	$(RM) $(DESTDIR)$(SYSTEMDDIR)/system/ldm.service

.PHONY: all debug clean mrproper install install-main install-config install-systemd uninstall
